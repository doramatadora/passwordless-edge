// Note: This script uses @simplewebauthn/browser, a lightweight wrapper around
// the Web Authentication API: https://simplewebauthn.dev/docs/packages/browser
const {
  browserSupportsWebAuthn,
  platformAuthenticatorIsAvailable,
  startRegistration,
  browserSupportsWebAuthnAutofill,
  startAuthentication
} = SimpleWebAuthnBrowser

const COMPAT_MESSAGE = document.getElementById('passkeyNotSupported')
const PASSKEY_SUPPORTED = document.getElementById('passkeySupported')
const PASSKEY_FORM = document.getElementById('passkeyForm')
const REGISTER_BUTTON = document.getElementById('register')
const AUTHENTICATE_BUTTON = document.getElementById('authenticate')
const USER_NAME = document.getElementById('name')
const ANNOUNCER = document.getElementById('announcer')

const announce = (msg, keepMs = 3000) => {
  ANNOUNCER.innerText = msg
  ANNOUNCER.style.display = 'block'
  setTimeout(() => {
    ANNOUNCER.style.display = 'none'
  }, keepMs)
}

// Feature detection: Does this browser support passkeys (WebAuthn)?
if (browserSupportsWebAuthn()) {
  // Uncomment if you exclusively want to support platform authenticators
  // (e.g. Face ID, Windows Hello, Android fingerprint unlock etc.)
  // ;(async () => {
  //   if (await platformAuthenticatorIsAvailable()) {
      // Display the form to register or authenticate.
      PASSKEY_SUPPORTED.style.display = 'block'

      /**
       * Registration
       */
      REGISTER_BUTTON.addEventListener('click', async e => {
        e.preventDefault()
        if (!USER_NAME.value.length) {
          announce(`Please enter a username`, 2000)
          USER_NAME.focus()
          return
        }

        // The front end's primary job during registration is the following:
        // 1. Get registration options from the Relying Party server (Compute@Edge)
        // 2. Submit registration options to the authenticator
        // 3. Submit the authenticator's response to the Relying Party for verification

        try {
          // 1. Get registration options from the Relying Party (RP) server.
          const regOptionsResp = await fetch('/registration/options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              username: USER_NAME.value
            })
          })
          const regOptions = await regOptionsResp.json()
          console.debug('Registration options from RP', regOptions)

          // 2. Submit registration options to the authenticator.
          const regResp = await startRegistration(regOptions.publicKey)
          console.debug('Registration response from authenticator', regResp)

          // 3. Submit the authenticator's response to the Relying Party for verification.
          const regVerifyResp = await fetch('/registration/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              username: USER_NAME.value,
              authenticatorResponse: regResp
            })
          })
          console.debug(
            'Registration verification response from RP',
            regVerifyResp
          )

          if (regVerifyResp.ok === true) {
            announce(`Success! Now try to authenticate...`)
          } else {
            announce(`Registration failed`)
          }
        } catch (err) {
          announce(`Error: ${err.message}`)
          throw err
        }
      })

      /**
       * Authentication
       */
      AUTHENTICATE_BUTTON.addEventListener('click', async e => {
        e.preventDefault()
        if (!USER_NAME.value.length) {
          announce(`Please enter a username`, 2000)
          USER_NAME.focus()
          return
        }

        // The front end's primary job during authentication is the following:
        // 1. Get authentication options from the Relying Party server (Compute@Edge)
        // 2. Submit authentication options to the authenticator
        // 3. Submit the authenticator's response to the Relying Party for verification
        try {
          // 1. Get authentication options from the Relying Party (RP) server.
          const authOptionsResp = await fetch('/authentication/options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              username: USER_NAME.value
            })
          })
          const authOptions = await authOptionsResp.json()
          console.debug('Authentication options from RP', authOptions)

          // 2. Submit authentication options to the authenticator.
          const authResp = await startAuthentication(authOptions.publicKey)
          console.debug('Authentication response from authenticator', authResp)

          // 3. Submit the authenticator's response to the Relying Party for verification.
          const authVerifyResp = await fetch('/authentication/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              username: USER_NAME.value,
              authenticatorResponse: authResp
            })
          })
          console.debug(
            'Authentication verification response from RP',
            authVerifyResp
          )

          if (authVerifyResp.ok === true) {
            announce(`Success! You're authenticated`)
          } else {
            announce(`Authentication failed`)
          }
        } catch (err) {
          announce(`Error: ${err.message}`)
          throw err
        }
      })
  // Uncomment if you exclusively want to support platform authenticators
  // (e.g. Face ID, Windows Hello, Android fingerprint unlock etc.)
  //   } else {
  //     announce(`User verifying platform authenticator is not available`)
  //     throw new Error(`User verifying platform authenticator is not available`)
  //   }
  // })()
} else {
  // Display message that passkeys are not supported.
  COMPAT_MESSAGE.style.display = 'block'
}
