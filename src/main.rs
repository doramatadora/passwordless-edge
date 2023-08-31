use fastly::http::{Method, StatusCode};
use fastly::{mime, Error, Request, Response};

const INDEX_HTML: &str = include_str!("client/index.html");
const STYLE_CSS: &str = include_str!("client/style.css");
const AUTH_JS: &[u8] = include_bytes!("client/auth.js");

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
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

        // REGISTRATION

        // 1. Provide the registration options + random challenge.
        (&Method::POST, "/registration/options") => {
            println!("Getting registration options");

            // 1.1 Retrieve the username from the request body.

            // 1.2.a. If the user is already registered and has any other credentials, 
            // exclude these from being re-registered.
            // 1.2.a.1. Exposed credentials may *only* provide a Uuid, and not the username!

            // 1.2.b. If the user is not already registered, generate a Uuid and store it 
            // in the KV Store, associated with the username.

            // 1.3. Generate a random challenge and its paired registration state, to be verified later.

            // 1.4. Store the registration state in the KV Store (safe: this is server-side).
            // Storing it in a cookie would be UNSAFE (open to replay attacks).

            // 1.5. Return the registration options + random challenge to the client.

            Ok(Response::from_status(StatusCode::OK))
        }

        // 2. Verify the registration response from the authenticator.
        // The client has completed the WebAuthn registration ceremony
        // and the user has created a key pair on their device, associated with this RP.
        // The RP must verify the signed challenge and persist the new credentials.
        (&Method::POST, "/registration/verify") => {
            println!("Verifying registration response from authenticator");

            // 2.1 Retrieve the username and authenticator_response from the request body.
            
            // 2.2. Retrieve Uuid for the username.

            // 2.3. Retrieve and deserialize registration state for the Uuid.

            // 2.4. Verify the authenticator_response.

            // 2.5. Retrieve any existing keys associated with the Uuid. 
            // Insert the new credential among them, and store the updated set of credentials
            // in the KV Store.

            Ok(Response::from_status(StatusCode::OK))
        }

        // AUTHENTICATION
        // Once a credential is stored, the RP can authenticate a user using that credential.

        // 1. Provide the authentication options + random challenge.
        (&Method::POST, "/authentication/options") => {
            println!("Getting authentication options");

            // 1.1 Retrieve the username from the request body.

            // 1.2. Retrieve Uuid for the username.

            // 1.3. Retrieve and deserialize the user's credentials set.
         
            // 1.4. Generate a random challenge and its paired authentication state, to be verified later.

            // 1.5. Store the authentication state in the KV Store (safe: this is server-side).
            // Storing it in a cookie would be UNSAFE (open to replay attacks).

            // 1.6. Return the authentication options + random challenge to the client.

            Ok(Response::from_status(StatusCode::OK))
        }

        // 2. Verify the authentication response from the authenticator.
        // The client has completed the WebAuthn credential retrieval + signing ceremony.
        // The RP must verify that the response from the authenticator matches the stored auth_state.
        (&Method::POST, "/authentication/verify") => {
            println!("Verifying authentication response from authenticator");

            // 2.1 Retrieve the username and authenticator_response from the request body.

            // 2.2. Retrieve Uuid for the username.

            // 2.3. Retrieve and deserialize authentication state for the Uuid.
          
            // 2.4. Verify the authenticator_response.

            // 2.5 Retrieve and update the key that was used from the user's set of credentials.
            // Some classes of key maintain an activation counter which allows (limited) 
            // protection against device cloning.

            // 2.6 Save the updated credential. The user is authenticated!
            
            Ok(Response::from_status(StatusCode::OK))
        }

        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)),
    }
}
