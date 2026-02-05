(function($) {

/**
 * Webauthn authentication and registration wiring to django
 * login form and django-two-factor authentication steps.
 *
 * @class SecurityKeys
 * @namespace window
 */

window.SecurityKeys = {

  /**
   * Initialize security keys integration
   * This should be called on the login process views
   * and the security key management views
   *
   * @method init
   */

  init : function(config) {

    this.config = config;

    this.init_two_factor();
    this.init_key_registration();

  },

  init_autofill : async function(config) {

    this.config = config;

    await this.init_passkey_autofill();
    this.init_passkey_button();

  },
  init_passkey_autofill : async function() {
    var self = this;
    var login_form = $(".login-form form")

    if (
      typeof window.PublicKeyCredential !== 'undefined'
      && typeof window.PublicKeyCredential.isConditionalMediationAvailable === 'function'
    ) {
      const available = await PublicKeyCredential.isConditionalMediationAvailable();
      var url = this.config.url_request_authentication;
      var payload = {for_login:true}
      payload.csrfmiddlewaretoken = this.config.csrf_token;

      if (available){
        $.post(url, payload, (response) => {

          response.challenge = base64url.decode(response.challenge);

          // Store the abort controller so we can cancel the autofill request
          self.autofillAbortController = new AbortController();
          var assertion = navigator.credentials.get({
            publicKey: response,
            mediation: "conditional",
            signal: self.autofillAbortController.signal
          });
          assertion.catch((exc) => {
            // Ignore AbortError - it's expected when button is clicked
            if(exc.name !== "AbortError" && error)
              error(exc);
          });
          assertion.then((PublicKeyCredential) => {
            const decoder = new TextDecoder();
            var credentials = {
              id: PublicKeyCredential.id,
              rawId: base64url.encode(PublicKeyCredential.rawId),
              response: {
                authenticatorData: base64url.encode(PublicKeyCredential.response.authenticatorData),
                clientDataJSON: base64url.encode(PublicKeyCredential.response.clientDataJSON),
                signature: base64url.encode(PublicKeyCredential.response.signature),
                userHandle: decoder.decode(PublicKeyCredential.response.userHandle)
              },
              type: PublicKeyCredential.type
            }
    
            payload.credential = JSON.stringify(credentials);
            login_form.append($('<input type="hidden" name="credential">').val(payload.credential));
            login_form.submit();
          });
    
        });
      }
    }
  },

  /**
   * Initialize explicit passkey login button
   *
   * This adds a click handler to the passkey login button that
   * triggers the WebAuthn authentication flow
   *
   * @method init_passkey_button
   */
  init_passkey_button : function() {
    var self = this;
    var login_form = $(".login-form form");
    var passkey_button = $("#passkey-login-button");

    if (!passkey_button.length) {
      return;
    }

    passkey_button.click(function(ev) {
      ev.preventDefault();

      // Abort any pending autofill request first
      if (self.autofillAbortController) {
        self.autofillAbortController.abort();
        self.autofillAbortController = null;

        // Give the browser a moment to release the WebAuthn lock
        setTimeout(function() {
          self.request_authenticate(
            null,
            true,
            (payload) => {
              login_form.append($('<input type="hidden" name="credential">').val(payload.credential));
              login_form.submit();
            },
            () => {
              alert(gettext("No passkey credentials found. Please use username and password to login."));
            },
            (exc) => {
              // Error or user canceled
            }
          );
        }, 10);
      } else {
        // No autofill active, proceed immediately
        self.request_authenticate(
          null,
          true,
          (payload) => {
            login_form.append($('<input type="hidden" name="credential">').val(payload.credential));
            login_form.submit();
          },
          () => {
            alert(gettext("No passkey credentials found. Please use username and password to login."));
          },
          (exc) => {
            // Error or user canceled
          }
        );
      }
    });
  },

  /**
   * Convert array-buffer to uint8 array
   *
   * @method array_buffer_to_uint8
   * @param {ArrayBuffer} b
   * @returns {Uint8Array}
   */

  array_buffer_to_uint8 : function(b){
    return Uint8Array.from(b, c=>c.charCodeAt(0));
  },

  /**
   * base64-url encode from array-buffer
   *
   * @method array_buffer_to_base64
   * @param {ArrayBuffer} b
   * @returns {String}
   */

  array_buffer_to_base64 : function(b) {
    return base64url.encode(b);
  },

  /**
   * base64-url decode to array-buffer
   *
   * @method base64_to_array_buffer
   * @param {String} b
   * @returns {ArrayBuffer}
   */

  base64_to_array_buffer : function(b) {
    return base64url.decode(b);
  },

  /**
   * Initializes security keys for django-two-factor
   *
   * Called automatically by `init()`
   *
   * @method init_two_factor
   */

  init_two_factor : function() {

    var form = $(".login-form form")
    var initiator = $('div[data-2fa-method="security-key"]')
    var button_select_u2f = form.find('button[data-device-step="security-key"]')

    // if totp method exists and is active, there will be a button
    // to select security-key authentication as an alternative method
    //
    // wire this button to go to the 'security-key' authentication step

    button_select_u2f.click(function(ev) {
      ev.preventDefault();
      form.append($('<input type="hidden" name="wizard_goto_step">').val("security-key"));
      form.submit();
    });


    if(!initiator.length) {
      return;
    }

    var username = initiator.data("username")
    var button_next = form.find('button[type="submit"].btn-primary');
    var button_back = form.find('button[type="submit"].btn-secondary');
    button_next.prop("disabled", true);

    // Request authentication options from server

    SecurityKeys.request_authenticate(
      username,
      false,
      (payload) => {

        // authentication options received and webauthn credentials
        // retrieved.
        //
        // attach credentials to form and submit to authenticate

        form.find("#id_security-key-credential").val(payload.credential)
        form.submit()

      },
      () => {

        // no credentials could be obtains

        alert(gettext("No credentials provided"));

        // go to the previous 2fa wizard step

        button_back.trigger("click");
      },
      (exc) => {

        // webauthn raised an error or user canceled the process

        alert(gettext("Security key authentication aborted, returning to login."));

        // go to the previous 2fa wizard step

        button_back.trigger("click");
      }

    );
  },

  init_key_registration: function() {
    var form = $('#register-key-form');
    if(!form.length)
      return;

    var button = form.find('#register-key-form-submit');

    var submit = function(ev) {
      ev.preventDefault();
      SecurityKeys.request_registration(
        (credential) => {
          form.find($('input[name="credential"]').val(credential));
          form.submit();
        },
        (exc) => {
          console.log(exc);
        }
      );
      return false;
    }

    button.click(submit);
    form.find('input').keydown(function(ev) {
      if(ev.which == 13)
        submit(ev);
    });

  },

  /**
   * SecurityKey authentication process
   *
   * Will request authentication options from the server and then start
   * the webauthn process for the user
   *
   * @method request_authenticate
   * @param {String} username
   * @param {Boolean} for_login if true flags that this is an authentication request
   *   for password-less login. If false, this is an authentication request for
   *   two-factor authentication
   * @param {Function} callback called when credentials were successfully obtained
   * @param {Function} no_credentials called when no credentials could be obtained
   * @param {Function} error called when webauthn raised an error or user aborted
   *   the webauthn process
   */


  request_authenticate: function(username, for_login, callback, no_credentials, error) {
    var payload = {};
    if(username)
      payload.username = username;
    if(for_login)
      payload.for_login = 1;
    if(ignore_credential_filter)
      payload.ignore_credential_filter = 1;

    var url = this.config.url_request_authentication;

    payload.csrfmiddlewaretoken = this.config.csrf_token;

    $.post(url, payload, (response) => {

      response.challenge = base64url.decode(response.challenge);

      $(response.allowCredentials).each(function() {
        this.id = base64url.decode(this.id);
      });

      if(!for_login && !response.allowCredentials.length) {
        if(no_credentials)
          return no_credentials();
        return;
      }

      var assertion = navigator.credentials.get({publicKey: response});
      assertion.catch((exc) => {
        if(error)
          error(exc);
      });
      assertion.then((PublicKeyCredential) => {
        const decoder = new TextDecoder();

        // Handle userHandle - it can be null for 2FA security keys
        var userHandle = null;
        if (PublicKeyCredential.response.userHandle) {
          userHandle = decoder.decode(PublicKeyCredential.response.userHandle);
        }

        var credentials = {
          id: PublicKeyCredential.id,
          rawId: base64url.encode(PublicKeyCredential.rawId),
          response: {
            authenticatorData: base64url.encode(PublicKeyCredential.response.authenticatorData),
            clientDataJSON: base64url.encode(PublicKeyCredential.response.clientDataJSON),
            signature: base64url.encode(PublicKeyCredential.response.signature),
            userHandle: userHandle
          },
          type: PublicKeyCredential.type
        }

        payload.credential = JSON.stringify(credentials);
        callback(payload)

      });

    });
  },

  /**
   * Converts a Base64 encoded string to an ArrayBuffer.
   *
   * This function takes a Base64 encoded string as input and converts it to an ArrayBuffer. 
   * It first decodes the Base64 string into a binary string, then creates an ArrayBuffer 
   * of the appropriate size and populates it with the decoded bytes.
   *
   * Note:
   * - The function replaces '_' with '/' and '-' with '+' in the input string to handle URL-safe Base64 encoding.
   * - If the input string is `null`, the function returns `null`.
   *
   * @param {string} b64_encoded_string - The Base64 encoded string to be converted.
   * @returns {ArrayBuffer|null} The resulting ArrayBuffer containing the decoded bytes, 
   * or `null` if the input is `null`.
   */
  b64str2ab : function(b64_encoded_string) {
      if (b64_encoded_string == null) {
          return null;
      };

      let string = atob(b64_encoded_string.replace(/_/g, '/').replace(/-/g, '+')),
          buf = new ArrayBuffer(string.length),
          bufView = new Uint8Array(buf);
      for (var i = 0, strLen = string.length; i < strLen; i++) {
          bufView[i] = string.charCodeAt(i);
      }
      return buf;
  },

  /**
   * Security key registration process
   *
   * Will request registration options from the server and then start
   * the webauthn process for the user
   *
   * @method request_registration
   * @param {String} password user's current password for verification
   * @param {Function} callback called when credentials were successfully obtained
   * @param {Function} error called when webauthn raised an error or user aborted
   *   the process
   */

  request_registration: function(password, callback, error) {
    // initial step of security key registration
    //
    // request credential registration options from the server

    var url = this.config.url_request_registration;
    var payload = {
      password: password,
      csrfmiddlewaretoken: this.config.csrf_token
    };

    $.post(url, payload, (response) => {
      var challenge_str = SecurityKeys.base64_to_array_buffer(response.challenge);
      response.challenge = challenge_str;
      response.user.id = SecurityKeys.array_buffer_to_uint8(response.user.id);
      response.excludeCredentials.forEach((credential) => {
          credential.id = SecurityKeys.b64str2ab(credential.id);
      });
      navigator.credentials.create(
        {publicKey: response}
      ).then((credential) => {
        var credential_json = JSON.stringify({
          id: credential.id,
          rawId: SecurityKeys.array_buffer_to_base64(credential.rawId),
          response: {
            clientDataJSON: SecurityKeys.array_buffer_to_base64(
              credential.response.clientDataJSON
            ),
            attestationObject: SecurityKeys.array_buffer_to_base64(
              credential.response.attestationObject
            )
          },
          type: credential.type
        });

        callback(credential_json, credential, response);

      }).catch( (exc) => {
        if(error)
          error(exc);
        console.error(exc);
      });

    }).fail((xhr) => {
      // Handle password validation failure
      // Error message extraction with multiple fallback patterns:
      // 1. response.non_field_errors[0] - Django form validation errors from views
      // 2. response.meta.error - peeringdb middleware rate limiting errors
      // 3. Default fallback message for unexpected error formats
      if(error) {
        var response = xhr.responseJSON || {};
        var message = (response.non_field_errors && response.non_field_errors[0])
                   || (response.meta && response.meta.error)
                   || "Password verification failed";
        error({message: message, status: xhr.status});
      }
    });
  },


}


})(jQuery);
