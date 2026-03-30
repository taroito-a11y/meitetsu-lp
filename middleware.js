export const config = {
  matcher: "/(.*)",
};

function unauthorized() {
  return new Response("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Protected Area", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
}

export default function middleware(request) {
  const username = process.env.BASIC_AUTH_USER;
  const password = process.env.BASIC_AUTH_PASSWORD;

  if (!username || !password) {
    return new Response(
      "Basic auth is not configured. Set BASIC_AUTH_USER and BASIC_AUTH_PASSWORD.",
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }

  const authorization = request.headers.get("authorization");
  if (!authorization || !authorization.startsWith("Basic ")) {
    return unauthorized();
  }

  const expected = `Basic ${btoa(`${username}:${password}`)}`;
  if (authorization !== expected) {
    return unauthorized();
  }

  return;
}
