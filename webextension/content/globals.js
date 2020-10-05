//globals from main.js cannot be overridden in nodejs unless we put them in a separate file
var chosen_notary;
var is_chrome = window.navigator.userAgent.match('Chrome') ? true : false;
