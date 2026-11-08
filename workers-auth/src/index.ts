import { WorkOS } from '@workos-inc/node';

type Env = {
	WORKOS_API_KEY: string;
	WORKOS_CLIENT_ID: string;
	WORKOS_REDIRECT_URI: string;
	WORKOS_COOKIE_PASSWORD?: string;
	APP_RETURN_TO?: string;
	ALLOWED_ORIGINS?: string;
	WORKOS_PROVIDER?: string;
	AUTH_SESSIONS?: KVNamespace;
};

const PKCE_STATE_PREFIX = 'pkce:';
const SESSION_PREFIX = 'session:';
const PKCE_TTL_SECONDS = 10 * 60; // 10 minutes
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days

export default {
	async fetch(request, env): Promise<Response> {
		if (request.method === 'OPTIONS') {
			return handleOptions(env, request);
		}

		const url = new URL(request.url);

		try {
			switch (url.pathname) {
				case '/auth/login':
					return await handleLogin(env, request, url);
				case '/auth/callback':
					return await handleCallback(env, request, url);
				case '/auth/session':
					return await handleSession(env, request);
				case '/finish':
					return handleFinish();
				default:
					return jsonResponse(env, { error: 'Not Found' }, 404);
			}
		} catch (error) {
			console.error('Auth worker error:', error);
			const message = error instanceof Error ? error.message : 'Unknown error';
			return jsonResponse(env, { error: 'Internal Server Error', details: message }, 500);
		}
	},
} satisfies ExportedHandler<Env>;

async function handleLogin(env: Env, request: Request, url: URL): Promise<Response> {
	assertEnv(env, ['WORKOS_API_KEY', 'WORKOS_CLIENT_ID', 'WORKOS_REDIRECT_URI']);

	const workos = new WorkOS(env.WORKOS_API_KEY);
	const codeVerifier = generateRandomString(64);
	const codeChallenge = await generateCodeChallenge(codeVerifier);
	const state = crypto.randomUUID();
	const returnTo = url.searchParams.get('return_to') ?? env.APP_RETURN_TO ?? null;
	const loginHint = url.searchParams.get('login_hint') ?? undefined;
	const provider = url.searchParams.get('provider') ?? env.WORKOS_PROVIDER ?? 'AuthKit';
	const organizationId = url.searchParams.get('organization_id') ?? undefined;
	const connectionId = url.searchParams.get('connection_id') ?? undefined;

	await persistPkceValues(env, state, {
		codeVerifier,
		returnTo,
	});

	const authorizationUrl = workos.userManagement.getAuthorizationUrl({
		clientId: env.WORKOS_CLIENT_ID,
		redirectUri: env.WORKOS_REDIRECT_URI,
		codeChallenge,
		codeChallengeMethod: 'S256',
		state,
		loginHint,
		provider,
		organizationId,
		connectionId,
	});

	return Response.redirect(authorizationUrl, 302);
}

async function handleCallback(env: Env, request: Request, url: URL): Promise<Response> {
	assertEnv(env, ['WORKOS_API_KEY', 'WORKOS_CLIENT_ID']);

	const code = url.searchParams.get('code');
	const state = url.searchParams.get('state');

	if (!code || !state) {
		return jsonResponse(env, { error: 'Missing code or state' }, 400);
	}

	const stored = await readPkceValues(env, state);
	if (!stored) {
		return jsonResponse(env, { error: 'State expired or invalid' }, 400);
	}

	await deletePkceValues(env, state);

	const workos = new WorkOS(env.WORKOS_API_KEY);
	const authenticateOptions = {
		clientId: env.WORKOS_CLIENT_ID,
		code,
		codeVerifier: stored.codeVerifier,
		ipAddress: request.headers.get('CF-Connecting-IP') ?? undefined,
		userAgent: request.headers.get('user-agent') ?? undefined,
		session: env.WORKOS_COOKIE_PASSWORD
			? {
				sealSession: true,
				cookiePassword: env.WORKOS_COOKIE_PASSWORD,
			}
			: undefined,
	};

	const authentication = await workos.userManagement.authenticateWithCodeAndVerifier(
		authenticateOptions,
	);

	const sessionToken = crypto.randomUUID();
	await persistSession(env, sessionToken, {
		user: authentication.user,
		authenticationMethod: authentication.authenticationMethod,
		organizationId: authentication.organizationId ?? null,
		accessToken: authentication.accessToken,
		refreshToken: authentication.refreshToken,
		sealedSession: authentication.sealedSession ?? null,
		expiresAt: computeExpiry(authentication),
	});

	const defaultReturnTo = env.APP_RETURN_TO ?? new URL('/finish', url.origin).toString();
	const returnUrl = stored.returnTo ?? defaultReturnTo;
	if (returnUrl) {
		const redirectUrl = new URL(returnUrl);
		redirectUrl.searchParams.set('session_token', sessionToken);
		return Response.redirect(redirectUrl.toString(), 302);
	}

	return jsonResponse(env, { sessionToken });
}

async function handleSession(env: Env, request: Request): Promise<Response> {
	const method = request.method.toUpperCase();
	const sessionToken = extractSessionToken(request);

	if (!sessionToken) {
		return jsonResponse(env, { error: 'Missing session token' }, 401);
	}

	if (method === 'GET') {
		const session = await readSession(env, sessionToken);
		if (!session) {
			return jsonResponse(env, { error: 'Session not found' }, 401);
		}
		return jsonResponse(env, { session });
	}

	if (method === 'DELETE') {
		await deleteSession(env, sessionToken);
		return jsonResponse(env, { success: true });
	}

	return jsonResponse(env, { error: 'Method not allowed' }, 405);
}

function extractSessionToken(request: Request): string | null {
	const auth = request.headers.get('authorization');
	if (auth?.startsWith('Bearer ')) {
		return auth.substring('Bearer '.length).trim();
	}

	const url = new URL(request.url);
	return url.searchParams.get('session_token');
}

type StoredPkce = {
	codeVerifier: string;
	returnTo: string | null;
};

type StoredSession = {
	user: unknown;
	authenticationMethod?: string;
	organizationId: string | null;
	accessToken: string;
	refreshToken: string;
	sealedSession: string | null;
	expiresAt: string | null;
};

async function persistPkceValues(env: Env, state: string, value: StoredPkce): Promise<void> {
	if (!env.AUTH_SESSIONS) {
		console.warn('AUTH_SESSIONS KV binding is not configured');
		return;
	}
	await env.AUTH_SESSIONS.put(PKCE_STATE_PREFIX + state, JSON.stringify(value), {
		expirationTtl: PKCE_TTL_SECONDS,
	});
}

async function readPkceValues(env: Env, state: string): Promise<StoredPkce | null> {
	if (!env.AUTH_SESSIONS) {
		return null;
	}
	const data = await env.AUTH_SESSIONS.get(PKCE_STATE_PREFIX + state, { type: 'json' });
	return (data as StoredPkce | null) ?? null;
}

async function deletePkceValues(env: Env, state: string): Promise<void> {
	if (!env.AUTH_SESSIONS) {
		return;
	}
	await env.AUTH_SESSIONS.delete(PKCE_STATE_PREFIX + state);
}

async function persistSession(env: Env, token: string, value: StoredSession): Promise<void> {
	if (!env.AUTH_SESSIONS) {
		console.warn('AUTH_SESSIONS KV binding is not configured');
		return;
	}
	await env.AUTH_SESSIONS.put(SESSION_PREFIX + token, JSON.stringify(value), {
		expirationTtl: SESSION_TTL_SECONDS,
	});
}

async function readSession(env: Env, token: string): Promise<StoredSession | null> {
	if (!env.AUTH_SESSIONS) {
		return null;
	}
	const data = await env.AUTH_SESSIONS.get(SESSION_PREFIX + token, { type: 'json' });
	return (data as StoredSession | null) ?? null;
}

async function deleteSession(env: Env, token: string): Promise<void> {
	if (!env.AUTH_SESSIONS) {
		return;
	}
	await env.AUTH_SESSIONS.delete(SESSION_PREFIX + token);
}

function computeExpiry(authentication: {
	accessToken?: string;
	refreshToken?: string;
}): string | null {
	if (!authentication.accessToken) {
		return null;
	}

	// Access tokens expire after 1 hour by default.
	return new Date(Date.now() + 60 * 60 * 1000).toISOString();
}

function generateRandomString(length: number): string {
	const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
	const randomValues = new Uint8Array(length);
	crypto.getRandomValues(randomValues);
	let result = '';
	for (const value of randomValues) {
		result += charset[value % charset.length];
	}
	return result;
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(codeVerifier);
	const digest = await crypto.subtle.digest('SHA-256', data);
	return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function handleOptions(env: Env, request: Request): Response {
	const headers = buildCorsHeaders(env, request.headers.get('Origin'));
	return new Response(null, { headers });
}

function handleFinish(): Response {
	const html = `<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<title>Authentication Complete</title>
		<meta name="viewport" content="width=device-width, initial-scale=1" />
		<style>
			body { font-family: system-ui, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }
			main { max-width: 520px; margin: 0 auto; padding: 32px; background: rgba(15, 23, 42, 0.82); border-radius: 16px; box-shadow: 0 18px 45px rgba(2, 6, 23, 0.45); }
			h1 { margin-bottom: 12px; }
			code { display: block; margin-top: 12px; padding: 12px; border-radius: 8px; background: rgba(30, 41, 59, 0.9); word-break: break-all; }
			button { margin-top: 20px; padding: 10px 16px; border: none; border-radius: 8px; background: #2563eb; color: #fff; font-weight: 600; cursor: pointer; }
			button:hover { background: #1d4ed8; }
			p { line-height: 1.5; }
		</style>
	</head>
	<body>
		<main>
			<h1>Authentication Complete</h1>
			<p id="message">Looking for your session token...</p>
			<code id="token" hidden></code>
			<button id="copy" hidden>Copy session token</button>
			<p style="margin-top:24px;">Next steps:</p>
			<ol>
				<li>Copy the session token above.</li>
				<li>Send it from your Expo app to <code style="display:inline; padding:2px 6px;">/auth/session</code>.</li>
				<li>Store the user + tokens the API returns.</li>
			</ol>
		</main>
		<script>
			(function() {
				const params = new URLSearchParams(window.location.search);
				const token = params.get('session_token');
				const messageEl = document.getElementById('message');
				const tokenEl = document.getElementById('token');
				const copyBtn = document.getElementById('copy');

				if (!token) {
					messageEl.textContent = 'No session token found. Restart the sign-in flow.';
					return;
				}

				tokenEl.textContent = token;
				tokenEl.hidden = false;
				copyBtn.hidden = false;
				messageEl.textContent = 'Copy this session token and use it in your app:';

				copyBtn.addEventListener('click', async () => {
					try {
						await navigator.clipboard.writeText(token);
						copyBtn.textContent = 'Copied!';
						setTimeout(() => (copyBtn.textContent = 'Copy session token'), 2000);
					} catch (err) {
						copyBtn.textContent = 'Copy failed';
					}
				});
			})();
		</script>
	</body>
</html>`;

	return new Response(html, {
		headers: {
			'Content-Type': 'text/html; charset=utf-8',
		},
	});
}

function jsonResponse(env: Env, body: unknown, status = 200): Response {
	const headers = buildCorsHeaders(env, null);
	headers.set('Content-Type', 'application/json');
	return new Response(JSON.stringify(body), { status, headers });
}

function buildCorsHeaders(env: Env, origin: string | null): Headers {
	const headers = new Headers();
	const allowOrigin = resolveAllowedOrigin(env, origin);
	headers.set('Access-Control-Allow-Origin', allowOrigin);
	headers.set('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
	headers.set('Access-Control-Allow-Headers', 'Authorization,Content-Type');
	headers.set('Access-Control-Allow-Credentials', 'true');
	return headers;
}

function resolveAllowedOrigin(env: Env, requestOrigin: string | null): string {
	const configured = env.ALLOWED_ORIGINS?.split(',').map((origin) => origin.trim()).filter(Boolean);
	if (!configured || configured.length === 0) {
		return '*';
	}

	if (!requestOrigin) {
		return configured[0];
	}

	return configured.includes(requestOrigin) ? requestOrigin : configured[0];
}

function assertEnv(env: Env, keys: Array<keyof Env>): void {
	const missing = keys.filter((key) => !env[key]);
	if (missing.length > 0) {
		throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
	}
}
