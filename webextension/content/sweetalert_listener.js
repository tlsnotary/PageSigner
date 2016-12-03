chrome.runtime.onMessage.addListener(function(data) {
  if (data.destination !== 'sweetalert') return;
  swal(data.args);
});
