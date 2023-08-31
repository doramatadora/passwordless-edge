use fastly::http::{Method, StatusCode};
use fastly::{mime, Error, Request, Response};

const INDEX_HTML: &str = include_str!("client/index.html");
const STYLE_CSS: &str = include_str!("client/style.css");
const AUTH_JS: &[u8] = include_bytes!("client/auth.js");

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {

    match (req.get_method(), req.get_path()) {
        // FRONTEND
        (&Method::GET, "/style.css") => {
            Ok(Response::from_body(STYLE_CSS).with_content_type(fastly::mime::TEXT_CSS))
        }
        (&Method::GET, "/auth.js") => {
            Ok(Response::from_body(AUTH_JS).with_content_type(mime::APPLICATION_JAVASCRIPT_UTF_8))
        }
        (&Method::GET, "/") => {
            Ok(Response::from_body(INDEX_HTML).with_content_type(mime::TEXT_HTML_UTF_8))
        }

        // Relying Party API
        // REGISTRATION

        // 1. Provide the registration options + random challenge.
        (&Method::POST, "/registration/options") => {
            println!("Getting registration options");

            Ok(Response::from_status(StatusCode::OK))
        }

        // 2. Validate the response from the authenticator against stored state.
        // The client has completed the WebAuthn registration ceremony
        // and the user has created a key pair on their device, associated with this RP.
        // The RP must verify the signed challenge and persist the new credentials.
        (&Method::POST, "/registration/verify") => {
            println!("Verifying registration response from authenticator");

            Ok(Response::from_status(StatusCode::OK))
        }

        // AUTHENTICATION
        // Once a credential is stored, the RP can authenticate a user using that credential.

        // 1. Provide the authentication options + random challenge.
        (&Method::POST, "/authentication/options") => {
            println!("Getting authentication options");

            Ok(Response::from_status(StatusCode::OK))
        }

        // 2. Validate the response from the authenticator against stored state.
        // The client has completed the WebAuthn credential retrieval + signing ceremony.
        // The RP must verify the signed challenge before the user is considered signed-in.
        (&Method::POST, "/authentication/verify") => {
            println!("Verifying authentication response from authenticator");

            Ok(Response::from_status(StatusCode::OK))
        }

        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)),
    }
}
