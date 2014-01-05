-record(struct, {lst=[]}).
-define(AFTER_LOGIN, case wf:config(login) of unknown -> "/account"; P -> P end).
-define(LOGIN_PAGE, "/login").
-define(METHODS, [facebook,google,github,twitter,microsoft,passaporte_web]).
-define(API,[sdk/0,               % JavaScript for page embedding for JavaScript based login methods
             login_button/0,      % HTML Button for page embedding
             event/1,             % Page Event for HTTP redirect based login methods
             api_event/3,         % Page Event for JavaScript based login methods
             email_prop/2,
             callback/0,          % Callback part of HTTP redirect based login methods
             registration_data/3  % Process Parameters
            ]).
