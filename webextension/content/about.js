var link1 = document.getElementById("link1");
link1.addEventListener("click", function(evt) {
  sendMessage({
    'destination': 'extension',
    'message': 'openLink1'
  });
  window.close();
});
