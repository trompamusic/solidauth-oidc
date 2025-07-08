def get_sample_client_registration(baseurl, redirect_urls):
    if not baseurl.endswith("/"):
        baseurl += "/"

    sample_client_registration = {
        "client_name": "Solid OIDC test app",
        "redirect_uris": redirect_urls,
        "post_logout_redirect_uris": [baseurl + "logout"],
        "client_uri": baseurl,
        "logo_uri": baseurl + "logo.png",
        "tos_uri": baseurl + "tos.html",
        "scope": "openid webid offline_access",
        "grant_types": ["refresh_token", "authorization_code"],
        "response_types": ["code"],
        "default_max_age": 3600,
        "require_auth_time": True,
    }
    return sample_client_registration
