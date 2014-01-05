-module(passaporte_web).
-author('Vitor Mazzi').
-include_lib("n2o/include/wf.hrl").
-include_lib("avz/include/avz.hrl").
-include_lib("kvs/include/users.hrl").
-compile(export_all).
-export(?API).
-define(HTTP_ADDRESS, application:get_env(web, http_address)).
-define(ENVIRONMENT, application:get_env(web, pweb_environemnt, {ok, "sandbox"})).
-define(CONSUMER_KEY, case application:get_env(web, pweb_consumer_key) of {ok, K} -> K;_-> "" end).
-define(CONSUMER_SECRET, case application:get_env(web, pweb_consumer_secret) of {ok, S} -> S; _-> "" end).
-define(CONSUMER, {?CONSUMER_KEY, ?CONSUMER_SECRET, hmac_sha1}).

registration_data(Props, passaporte_web, Ori)->
    Id = proplists:get_value(<<"uuid">>, Props),
    Email = email_prop(Props, passaporte_web),
    DisplayName = name_prop(Props, passaporte_web),
    Ori#user{id = Id,
             username = Email,
             display_name = DisplayName,
             avatar = proplists:get_value(<<"profile_image_url">>, Props),
             name = proplists:get_value(<<"first_name">>, Props),
             email = Email,
             surname = proplists:get_value(<<"last_name">>, Props),
             passaporte_web_id = Id,
             register_date = erlang:now(),
             status = ok }.

email_prop(Props, passaporte_web) ->
    Mail = proplists:get_value(<<"email">>, Props),
    L = wf:to_list(Mail),
    case avz_validator:is_email(L) of
        true -> L;
        false -> {error, "not an email address"}
    end.

name_prop(Props, passaporte_web) ->
    FirstName = proplists:get_value(<<"first_name">>, Props),
    LastName = proplists:get_value(<<"last_name">>, Props),
    Email = email_prop(Props, passaporte_web),
    FullName = FirstName ++ LastName,
    case FullName of
        "" -> Email;
        NotEmpty -> NotEmpty
    end.

callback() ->
    Token = wf:q(<<"oauth_token">>),
    Verifier = wf:q(<<"oauth_verifier">>),
    case wf:user() of
         undefined ->
            if (Token /= undefined) andalso ( Verifier/= undefined) ->
               case get_access_token(binary_to_list(Token), binary_to_list(Verifier)) of
                    not_authorized -> skip;
                    Props -> UserData = show(Props), avz:login(passaporte_web, UserData#struct.lst)
               end;
            true -> skip
            end;
         _ -> skip end.

login_button() -> #panel{class=["btn-group"], body=
    #link{id=pweblogin, class=[btn, "btn-info", "btn-large", "btn-lg"],
        body=[#i{class=[fa,"fa-passaporte-web","fa-lg","icon-passaporte-web", "icon-large"]}, <<"Passaporte Web">>],
        postback={passaporte_web,loginpassaporte_web}}}.

sdk() -> [].
api_event(_,_,_) -> ok.
event({passaporte_web,loginpassaporte_web}) ->
    case get_request_token() of
         {RequestToken, _, _} -> wf:redirect(authorize_url(RequestToken));
         {error, R} -> error_logger:info_msg("Passaporte Web request failed:", [R]), [] end.

get_request_token()->
  URL = get_passaporte_url(?ENVIRONMENT, "/sso/initiate/"),
  ApplicationHost = case ?HTTP_ADDRESS of
    {ok, Address} -> Address;
    _ -> ""
  end,
  CallbackUrl = ApplicationHost ++ "/login",
  Params = [{"oauth_callback", CallbackUrl}],
  case oauth:get(URL, Params, ?CONSUMER) of
    {ok, Response} ->
      Params = oauth:params_decode(Response),
      RequestToken = oauth:token(Params),
      RequestTokenSecret = oauth:token_secret(Params),
      CallbackConfirmed = proplists:get_value("oauth_callback_confirmed", Params),
      {RequestToken, RequestTokenSecret, CallbackConfirmed};
    {error, E}-> {error, E}
  end.

get_access_token(undefined, undefined)-> not_authorized;
get_access_token(undefined, _)-> not_authorized;
get_access_token(_, undefined)-> not_authorized;
get_access_token(Token, Verifier)->
  URL = get_passaporte_url(?ENVIRONMENT, "/sso/token/"),
  Signed = oauth:sign("GET", URL, [{"oauth_verifier", Verifier}], ?CONSUMER, Token, ""),
  {OauthParams, QueryParams} = lists:partition(fun({K, _}) -> lists:prefix("oauth_", K) end, Signed),
  Request = {oauth:uri(URL, QueryParams), [oauth:header(OauthParams)]},
  {ok, Response} = httpc:request(get, Request, [{autoredirect, false}], []),
  case Response of
    {HttpResponse, _, _}->
      case HttpResponse of
        {"HTTP/1.1",200,"OK"}->
          Params = oauth:params_decode(Response),
          Params;
        _ -> not_authorized
      end;
    _ -> not_authorized
  end.

authorize_url(RequestToken)->
    URL = get_passaporte_url(?ENVIRONMENT, "/sso/authorize/"),
    oauth:uri(URL, [{"oauth_token", RequestToken}]).

show(Props)->
  URI = get_passaporte_url(?ENVIRONMENT, "/sso/fetchuserdata/"),
  {ok, Response} = oauth:get(URI, [], ?CONSUMER, oauth:token(Props), oauth:token_secret(Props)),
  case Response of
    {HttpResponse, _, Body} ->
        case HttpResponse of
            {"HTTP/1.1", 200, "OK"} ->
                n2o_json:decode(Body);
            _ ->
                error
        end;
    _ -> error
  end.

service_item()->
  case nsm_db:get(user, wf:user()) of 
    {error, notfound} -> wf:redirect("login");
    {ok, #user{passaporte_web_id=UUID}} ->
      try service_btn(UUID) of
        Btn ->  #li{id=pwebServiceBtn, class=png, body=Btn}
      catch
        _:_ -> []
      end
  end.

service_btn(undefined) ->
  case get_request_token() of
    {RequestToken, _, _} ->
      [#image{image="/images/img-52.png"}, #span{body= <<"Passaporte Web">>},
      #link{class="btn", body=["<span>+</span>", "Add"], url=authorize_url(RequestToken)}];
    {error, R} -> error_logger:info_msg("Passaporte Web request failed:", [R]), []
  end;
service_btn(UUID)->
  case nsm_db:get(passaporte_web_oauth, UUID) of
    {error, notfound}->
      service_btn(undefined);
    {ok, #passaporte_web_oauth{token=Token, secret=TokenSecret}} when Token == undefined orelse TokenSecret == undefined ->
      service_btn(undefined);
    {ok, #passaporte_web_oauth{}} ->
      [#image{image="/images/img-52.png"}, #span{body= <<"Passaporte Web">>},
      #link{class="btn", body=["<span>-</span>", "Del"], postback={delete, passaporte_web}}]
  end.

delete()->
  case nsm_db:get(user, wf:user()) of
    {error, notfound} -> wf:redirect("login");
    {ok, #user{passaporte_web_id=UUID} = User} when UUID =/= undefined ->
      case nsm_db:get(passaporte_web_oauth, UUID) of
        {error, notfound} -> ok;
        {ok, #passaporte_web_oauth{}} ->
          nsm_db:put(User#user{passaporte_web_id = undefined}),
          %nsx_msg:notify(["system", "put"], User#user{passaporte_web_id = undefined}),
          nsm_sb:delete(passaporte_web_oauth, UUID),
          %nsx_msg:notify(["system", "delete"], {passaporte_web_oauth, UUID}),
          wf:update(pwebServiceBtn, service_btn(undefined))
      end;
    _ -> ok
  end.

get_passaporte_url(Environment, Path) ->
    Host = case Environment of
        {ok, "production"} -> "https://app.passaporteweb.com.br";
        {ok, "sandbox"} -> "http://sandbox.app.passaporteweb.com.br";
        _ -> {error, "Invalid environment name"}
    end,
    Host ++ Path.
