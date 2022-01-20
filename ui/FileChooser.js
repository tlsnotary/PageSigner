/* global chrome*/

// class FileChooser create a "choose file" button and sends the chosen file
// to the extension
export class FileChooser{
  // show is called by extension's Main.openFileChooser()
  show(){
    const label = document.getElementById('import_label');
    label.style.display = '';
    const that = this;
    document.getElementById('import').addEventListener('change', function(evt) {
      const f = evt.target.files[0];
      if (f) {
        const reader = new FileReader();
        reader.onload = that.onload;
        reader.readAsArrayBuffer(f);
      }
    });
  }

  onload(e) {
    const loader = document.getElementById('loader');
    loader.classList.toggle('m-fadeIn');
    loader.removeAttribute('hidden');
    const import_label = document.getElementById('import_label');
    import_label.classList.toggle('m-fadeOut');
    chrome.runtime.sendMessage({
      destination: 'extension',
      message: 'import',
      data: Array.from(new Uint8Array(e.target.result))
    });
  // don't close the window, we reuse it to display html
  }
}