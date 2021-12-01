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

    this.init_passwordless_login();
    this.init_two_factor();
    this.init_key_registration();

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
   * Initializes password-less login support for django-login
   * form
   *
   * This is called automatically by `init()`
   *
   * @method init_passwordless_login()
   */

  init_passwordless_login : function() {
    var login_form = $(".login-form form")
    var login_step = login_form.find('[name="login_view-current_step"]');

    // normal or unknown django login (no django-two-factor wizard found)
    var normal_login = (login_form.length && !login_step.length);

    // django-two-factor login (wizard found and step is at "auth")
    var two_factor_login = (login_step.val() == "auth");

    if(normal_login || two_factor_login) {
      var button_next = login_form.find('button[type="submit"]').filter('.btn-login,.btn-primary');
      var fn_submit = function(ev) {
        var password = login_form.find("#id_auth-password, #id_password").val();
        var username= login_form.find("#id_auth-username, #id_username").val();

        if(password == "" && username != "") {

          // prevent default form submit since we need to wait
          // for credentials.
          ev.preventDefault();

          window.SecurityKeys.request_authenticate(
            username,
            true,

            (payload) => {

              // auth assertion successful, attach credentials

              login_form.append($('<input type="hidden" name="credential">').val(payload.credential));
              login_form.submit();

            },

            () => {

              console.log("No credentials for user");

              // no registered credentials

              login_form.submit();

            }
          );
        }
      };

      button_next.click(fn_submit);
      login_form.find('input').on('keydown', (ev) => {
        if(ev.which==13) {
          fn_submit(ev);
        }
      });
    }
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
    var i, payload = {username: username};
    if(for_login)
      payload.for_login = 1;

    url = this.config.url_request_authentication;

    payload.csrfmiddlewaretoken = this.config.csrf_token;

    $.post(url, payload, (response) => {

      response.challenge = base64url.decode(response.challenge);

      $(response.allowCredentials).each(function() {
        this.id = base64url.decode(this.id);
      });

      if(!response.allowCredentials.length) {
        if(no_credentials)
          return no_credentials();
        return;
      }

      assertion = navigator.credentials.get({publicKey: response});
      assertion.catch((exc) => {
        if(error)
          error(exc);
      });
      assertion.then((PublicKeyCredential) => {

        var credentials = {
          id: PublicKeyCredential.id,
          rawId: base64url.encode(PublicKeyCredential.rawId),
          response: {
            authenticatorData: base64url.encode(PublicKeyCredential.response.authenticatorData),
            clientDataJSON: base64url.encode(PublicKeyCredential.response.clientDataJSON),
            signature: base64url.encode(PublicKeyCredential.response.signature),
            userHandle: base64url.encode(PublicKeyCredential.response.userHandle)
          },
          type: PublicKeyCredential.type
        }

        payload.credential = JSON.stringify(credentials);
        callback(payload)

      });

    });
  },

  /**
   * Security key registration process
   *
   * Will request registration options from the server and then start
   * the webauthn process for the user
   *
   * @method request_registration
   * @param {Function} callback called when credentials were successfully obtained
   * @param {Function} error called when webauthn raised an error or user aborted
   *   the process
   */

  request_registration: function(callback, error) {
    // initial step of security key registration
    //
    // request credential registration options from the server

    var url = this.config.url_request_registration;

    $.get(url, (response)=> {
      var challenge_str = SecurityKeys.base64_to_array_buffer(response.challenge);
      response.challenge = challenge_str;
      response.user.id = SecurityKeys.array_buffer_to_uint8(response.user.id);
      const credential = navigator.credentials.create(
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
        container.editable("loading-shim", "hide");
        if(error)
          error(exc);
        console.error(exc);
      });

    });
  },


}


})(jQuery);
