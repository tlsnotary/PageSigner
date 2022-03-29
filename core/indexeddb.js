/* eslint-disable no-unused-vars */
let db;
let db_blobs;

export async function init_db() {
  await new Promise(function(resolve, reject) {

    const dbReq = indexedDB.open('PageSigner', 1);
    dbReq.onupgradeneeded = function (event) {
      // Set the db variable to our database so we can use it!
      db = event.target.result;

      if (!db.objectStoreNames.contains('sessions')) {
        db.createObjectStore('sessions', { keyPath: 'creationTime', autoIncrement: true });
      }
      if (!db.objectStoreNames.contains('preferences')) {
        const preferences = db.createObjectStore('preferences', { keyPath: 'name', autoIncrement: true });
        preferences.add({name:'firstTimeInitCompletedv2', value:false});
        preferences.add({name:'parsedCircuits', value:{}});
        preferences.add({name:'trustedOracle', value:{}});
        preferences.add({name:'notaryServerVersion', value:16});
      }
    };
    dbReq.onsuccess = function (event) {
      db = event.target.result;
      resolve();
    };
    dbReq.onerror = function (event) {
      alert('error opening database ' + event.target.errorCode);
    };
  });

  await new Promise(function(resolve, reject) {

    // We must create a separate DB for blobs. Having a separate store is not a solution because
    // i/o operations a very slow when there's blobs in a db
    const dbReq2 = indexedDB.open('PageSigner_blobs', 1);
    dbReq2.onupgradeneeded = function (event) {
      // Set the db variable to our database so we can use it!
      db_blobs = event.target.result;
      if (!db_blobs.objectStoreNames.contains('sessions')) {
        db_blobs.createObjectStore('sessions', { keyPath: 'creationTime', autoIncrement: true });
      }
    };
    dbReq2.onsuccess = function (event) {
      db_blobs = event.target.result;
      resolve();
    };
    dbReq2.onerror = function (event) {
      alert('error opening database ' + event.target.errorCode);
    };

  });
}


export async function addNewPreference(key, value){
  // check if the preference already exists
  const allPreferences = await new Promise(function(resolve, reject) {

    const tx = db.transaction(['preferences'], 'readonly');
    const store = tx.objectStore('preferences');
    const req = store.getAll();

    req.onsuccess = function(event) {
    // The result of req.onsuccess is an array
      resolve(event.target.result);
    };
    req.onerror = function(event) {
      alert('error in cursor request ' + event.target.errorCode);
      reject('error in cursor request ' + event.target.errorCode);
    };
  });

  for (let pref of allPreferences){
    if (pref['name'] == key){
      return;
    }
  }

  // preference does not exist, add it
  await new Promise(function(resolve, reject) {
    const tx = db.transaction(['preferences'], 'readwrite');
    const store = tx.objectStore('preferences');
    store.add({name:key, value:value});
    tx.oncomplete = function() {
      resolve();
    };
    tx.onerror = function(event) {
      alert('error storing ' + event.target.errorCode);
      reject();
    };
  });
}


export async function deleteSession(session) {
  await new Promise(function(resolve, reject) {
    const tx = db.transaction(['sessions'], 'readwrite');
    const sessions = tx.objectStore('sessions');
    const req = sessions.delete(session);
    req.onsuccess = function(event) {
      resolve();
    };
  });
  await new Promise(function(resolve, reject) {
    const tx = db_blobs.transaction(['sessions'], 'readwrite');
    const sessions = tx.objectStore('sessions');
    const req = sessions.delete(session);
    req.onsuccess = function(event) {
      resolve();
    };
  });
}


export async function getAllSessions() {
  return await new Promise(function(resolve, reject) {

    console.log('begin db');
    const tx = db.transaction(['sessions'], 'readonly');
    const store = tx.objectStore('sessions');
    const req = store.getAll();

    req.onsuccess = function(event) {
    // The result of req.onsuccess is an array
      resolve(event.target.result);
      console.log('end db');
    };
    req.onerror = function(event) {
      alert('error in cursor request ' + event.target.errorCode);
      reject('error in cursor request ' + event.target.errorCode);
    };
  });
}



export async function saveNewSession(date, host, request, response, pgsg, options){
  await new Promise(function(resolve, reject) {
    const tx = db.transaction(['sessions'], 'readwrite');
    const store = tx.objectStore('sessions');
    let isImported = false;
    let isEdited = false;
    if (options != undefined){
      if (options.indexOf('imported') > -1) isImported = true;
      if (options.indexOf('edited') > -1) isEdited = true;
    }
    // sessionName can be changed by the user in the manager window
    store.add({
      creationTime: date,
      sessionName: host,
      serverName: host,
      isImported: isImported,
      isEdited: isEdited,
      version: 6});
    tx.oncomplete = function() {
      resolve();
    };
    tx.onerror = function(event) {
      alert('error storing note ' + event.target.errorCode);
      reject();
    };
  });
  await new Promise(function(resolve, reject) {
    const tx2 = db_blobs.transaction(['sessions'], 'readwrite');
    const store2 = tx2.objectStore('sessions');
    store2.add({
      creationTime: date,
      serverName:host,
      request:request,
      response:response,
      pgsg:pgsg});
    tx2.oncomplete = function() {
      resolve();
    };
    tx2.onerror = function(event) {
      alert('error storing note ' + event.target.errorCode);
      reject();
    };
  });
}


export async function getSession(idx){
  return await new Promise(function(resolve, reject) {

    const tx = db.transaction(['sessions'], 'readonly');
    const store = tx.objectStore('sessions');
    const req = store.get(idx);
    req.onsuccess = function(event) {
      const entry = event.target.result;
      if (entry) {
        console.log(entry);
        resolve(entry);
      } else {
        console.log('entry 1 not found');
        resolve(null);
      }
    };
    req.onerror = function(event) {
      console.log('error getting entry 1 ' + event.target.errorCode);
      reject('error getting entry 1 ' + event.target.errorCode);
    };

  });
}




// get data from blob store
export async function getSessionBlob(idx){

  return await new Promise(function(resolve, reject) {

    const tx = db_blobs.transaction(['sessions'], 'readonly');
    const store = tx.objectStore('sessions');
    const req = store.get(idx);
    req.onsuccess = function(event) {
      const entry = event.target.result;
      if (entry) {
        resolve(entry);
      } else {
        console.log('note 1 not found');
        resolve(null);
      }
    };
    req.onerror = function(event) {
      console.log('error getting entry 1 ' + event.target.errorCode);
      reject('error getting entry 1 ' + event.target.errorCode);
    };

  });
}


export async function getPref(pref){
  return await new Promise(function(resolve, reject) {

    let tx = db.transaction(['preferences'], 'readonly');
    let store = tx.objectStore('preferences');
    let req = store.get(pref);
    req.onsuccess = function(event) {
      let entry = event.target.result;
      if (entry) {
        console.log(entry);
        resolve(entry.value);
      } else {
        resolve(null);
      }
    };
    req.onerror = function(event) {
      console.log('error getting entry 1 ' + event.target.errorCode);
      reject('error getting entry 1 ' + event.target.errorCode);
    };

  });
}


export async function setPref(pref, newvalue) {
  await new Promise(function(resolve, reject) {

    const tx = db.transaction(['preferences'], 'readwrite');
    const store = tx.objectStore('preferences');
    const request = store.get(pref);

    request.onsuccess = function(event) {
      // Get the old value that we want to update
      const data = event.target.result;

      // update the value(s) in the object that you want to change
      data.value = newvalue;

      // Put this updated object back into the database.
      const requestUpdate = store.put(data);
      requestUpdate.onerror = function(event) {
        // Do something with the error
        reject();
      };
      requestUpdate.onsuccess = function(event) {
        // Success - the data is updated!
        resolve();
      };
    };
  });
}




export async function renameSession(id, newname) {
  await new Promise(function(resolve, reject) {
    // Start a database transaction and get the notes object store
    const tx = db.transaction(['sessions'], 'readwrite');
    const sessions = tx.objectStore('sessions');
    const request = sessions.get(id);

    request.onsuccess = function(event) {
      // Get the old value that we want to update
      const data = event.target.result;

      // update the value(s) in the object that you want to change
      data.sessionName = newname;

      // Put this updated object back into the database.
      const requestUpdate = sessions.put(data);
      requestUpdate.onerror = function(event) {
        // Do something with the error
        reject();
      };
      requestUpdate.onsuccess = function(event) {
        // Success - the data is updated!
        resolve();
      };
    };
  });
}