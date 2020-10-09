//globals from main.js cannot be overridden in nodejs unless we put them in a separate file
var chosen_notary;
var is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;
//Future use: use TLS extension when user selects it in options
var use_max_fragment_length = false;