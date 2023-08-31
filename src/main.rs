use fastly::http::{Method, StatusCode};
use fastly::{mime, Error, KVStore, Request, Response};
use webauthn_rs::prelude::*;
use serde::{Deserialize, Serialize};

const INDEX_HTML: &str = include_str!("client/index.html");
const STYLE_CSS: &str = include_str!("client/style.css");
const AUTH_JS: &[u8] = include_bytes!("client/auth.js");

const RP_ORIGIN: &str = "http://localhost:7676";
const RP_ID: &str = "localhost";

#[derive(Deserialize, Serialize, Debug)]
struct Form {
    username: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct RegResp {
    username: String,
    #[serde(rename = "authenticatorResponse")]
    authenticator_response: RegisterPublicKeyCredential,
}

#[derive(Deserialize, Serialize, Debug)]
struct AuthResp {
    username: String,
    #[serde(rename = "authenticatorResponse")]
    authenticator_response: PublicKeyCredential,
}

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    let rp_origin = Url::parse(RP_ORIGIN).expect("Invalid relying party URL");
    let builder = WebauthnBuilder::new(RP_ID, &rp_origin).expect("Invalud Webauthn config.");
    let webauthn = builder.build().expect("Failed to stand up Webauthn");

    // Usernames to Uuid mapping.
    let mut users = KVStore::open("userdata")?.unwrap();
    // Uuid to credential mapping.
    let mut keys = KVStore::open("credentials")?.unwrap();
    // Uuid to challenge mapping.
    let mut state = KVStore::open("challenges")?.unwrap();
   
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
            let form = req.take_body_json::<Form>().unwrap();

            let (user_id, exclude_credentials) = match users.lookup_str(&form.username) {
                Ok(Some(id)) => {
                    println!("Existing uuid for {} is {}", form.username, id);
                    match keys.lookup_str(&id) {
                        Ok(Some(creds)) => {
                            let existing: Vec<Passkey> = serde_json::from_str(&creds).unwrap();
                            (Uuid::try_parse(&id)?,
                        Some(existing.iter().map(
                            |sk| sk.cred_id().clone())
                            .collect::<Vec<CredentialID>>()))
                        },
                        _ => {
                            println!("No credentials found for {}", id);
                            (Uuid::try_parse(&id)?, None)
                        }
                    }
                },
                _ => {
                    let id = Uuid::new_v4();
                    users.insert(&form.username, id.to_string()).expect("Failed to register new Uuid.");
                    (id, None)
                }
            };

            let (reg_challenge, reg_state) = webauthn
                .start_passkey_registration(
                    user_id,
                    &form.username,
                    &form.username,
                    exclude_credentials
                )
                .expect("Failed to generate registration challenge.");

            state.insert(&user_id.to_string(), serde_json::to_string(&reg_state)?).expect("Failed to store registration state.");
            Ok(Response::from_status(StatusCode::OK).with_body_json(&reg_challenge)?)
        }

        // 2. Validate the response from the authenticator against stored state.
        // The client has completed the WebAuthn registration ceremony
        // and the user has created a key pair on their device, associated with this RP.
        // The RP must verify the signed challenge and persist the new credentials.
        (&Method::POST, "/registration/verify") => {
            println!("Verifying registration response from authenticator");

            let reg = req.take_body_json::<RegResp>().unwrap();

            let user_id = users.lookup_str(&reg.username).expect("User not found").unwrap();

            let st = state.lookup_str(&user_id).expect("State not found").unwrap();

            let reg_state = serde_json::from_str::<PasskeyRegistration>(&st).expect("Session corrupted");

            let passkey_registration = webauthn.finish_passkey_registration(&reg.authenticator_response, &reg_state).expect("Failed to finish registration");
            
            let credentials = match keys.lookup_str(&user_id) {
                Ok(Some(creds)) => creds,
                _ => "[]".to_owned()
            };
            
            let mut existing_keys = serde_json::from_str::<Vec<Passkey>>(&credentials).unwrap_or(vec![]);
            existing_keys.push(passkey_registration.clone());
            keys.insert(&user_id, serde_json::to_string(&existing_keys).unwrap()).expect("Failed to store credentials.");

            Ok(Response::from_status(StatusCode::OK))
        }

        // AUTHENTICATION
        // Once a credential is stored, the RP can authenticate a user using that credential.

        // 1. Provide the authentication options + random challenge.
        (&Method::POST, "/authentication/options") => {
            println!("Getting authentication options");
            let form = req.take_body_json::<Form>().unwrap();

            let user_id = users.lookup_str(&form.username).expect("User not found").unwrap();

            let credentials = keys.lookup_str(&user_id).expect("Credentials not found").unwrap();

            let allow_credentials = serde_json::from_str::<Vec<Passkey>>(&credentials).expect("Credentials corrupted");

            let (auth_challenge, auth_state) = webauthn
                .start_passkey_authentication(
                   &allow_credentials
                )
                .expect("Failed to generate authentication challenge.");

            state.insert(&user_id.to_string(), serde_json::to_string(&auth_state)?).expect("Failed to store authentication state.");

            Ok(Response::from_status(StatusCode::OK).with_body_json(&auth_challenge)?)
        }

        // 2. Validate the response from the authenticator against stored state.
        // The client has completed the WebAuthn credential retrieval + signing ceremony.
        // The RP must verify the signed challenge before the user is considered signed-in.
        (&Method::POST, "/authentication/verify") => {
            println!("Verifying authentication response from authenticator");

            let auth = req.take_body_json::<AuthResp>().unwrap();

            let user_id = users.lookup_str(&auth.username).expect("User not found").unwrap();

            let st = state.lookup_str(&user_id).expect("State not found").unwrap();

            let auth_state = serde_json::from_str::<PasskeyAuthentication>(&st).expect("Session corrupted");

            let auth_result = webauthn.finish_passkey_authentication(&auth.authenticator_response, &auth_state).expect("Failed to finish authentication");

            let credentials = keys.lookup_str(&user_id).expect("Credentials not found").unwrap();

            let mut updated_credentials = serde_json::from_str::<Vec<Passkey>>(&credentials).expect("Credentials corrupted");

            updated_credentials.iter_mut().for_each(|sk| {
                sk.update_credential(&auth_result);
            });

            keys.insert(&user_id, serde_json::to_string(&updated_credentials)?).expect("Failed to store credentials.");

            Ok(Response::from_status(StatusCode::OK))
        }

        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)),
    }
}
