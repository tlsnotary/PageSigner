
var db;
var db_blobs;


async function init_db() {
  return new Promise(function(resolve, reject) {

    var dbReq = indexedDB.open('PageSigner', 1);
    dbReq.onupgradeneeded = function (event) {
      // Set the db variable to our database so we can use it!  
      db = event.target.result;

      if (!db.objectStoreNames.contains('sessions')) {
        db.createObjectStore('sessions', { keyPath: 'creationTime', autoIncrement: true });
      }
      if (!db.objectStoreNames.contains('preferences')) {
        let preferences = db.createObjectStore('preferences', { keyPath: 'name', autoIncrement: true });
        preferences.add({name:'testing', value:false});
        preferences.add({name:'verbose', value:true});
        preferences.add({name:'verifiedOracles', value:[]});
      }
    };
    dbReq.onsuccess = function (event) {
      db = event.target.result;
      resolve()
    };
    dbReq.onerror = function (event) {
      alert('error opening database ' + event.target.errorCode);
    };
  }).
  then(function(){
    return new Promise(function(resolve, reject) {

      //We must create a separate DB for blobs. Having a separate store is not a solution because
      //i/o operations a very slow when there's blobs in a db
      var dbReq2 = indexedDB.open('PageSigner_blobs', 1);
      dbReq2.onupgradeneeded = function (event) {
        // Set the db variable to our database so we can use it!  
        db_blobs = event.target.result;
        if (!db_blobs.objectStoreNames.contains('sessions')) {
          db_blobs.createObjectStore('sessions', { keyPath: 'creationTime', autoIncrement: true });
        }
      };
      dbReq2.onsuccess = function (event) {
        db_blobs = event.target.result;
        resolve()
      };
      dbReq2.onerror = function (event) {
        alert('error opening database ' + event.target.errorCode);
      };

    })
  })
}


async function addNewPreference(key, value){
  //check if the preference already exists
  var p = new Promise(function(resolve, reject) {

    let tx = db.transaction(['preferences'], 'readonly');
    let store = tx.objectStore('preferences');
    let req = store.getAll();

    req.onsuccess = function(event) {
    // The result of req.onsuccess is an array
    resolve(event.target.result)
    console.log('end db')
    }
    req.onerror = function(event) {
    alert('error in cursor request ' + event.target.errorCode);
    reject('error in cursor request ' + event.target.errorCode)
    }
  })
  var allPreferences = await p;
  for (let pref of allPreferences){
    if (pref['name'] == key){
      return;
    }
  }
  //preference does not exist, add it
  return new Promise(function(resolve, reject) {
    let tx = db.transaction(['preferences'], 'readwrite');
    let store = tx.objectStore('preferences');
    store.add({name:key, value:value});
    tx.oncomplete = function() { 
      resolve();
    }
    tx.onerror = function(event) {
      alert('error storing ' + event.target.errorCode);
      reject();
    }
  })
}


//converts all binary pgsgs into json format
async function convert_db(){
  var all = new Promise(function(resolve, reject) {

    console.log('begin db')
    let tx = db_blobs.transaction(['sessions'], 'readwrite');
    let store = tx.objectStore('sessions');
    let req = store.getAll();

    req.onsuccess = function(event) {
      // The result of req.onsuccess is an array
      resolve(event.target.result)
      console.log('end db')
    }
    req.onerror = function(event) {
      alert('error in cursor request ' + event.target.errorCode);
      reject('error in cursor request ' + event.target.errorCode)
    }
  })

  var allSessions = await all;
  for (let session of allSessions){
    var id = session['creationTime']
    var p = new Promise(function(resolve, reject) {
  
      // Start a database transaction and get the object store
      let tx = db_blobs.transaction(['sessions'], 'readwrite');
      let sessions = tx.objectStore('sessions')
      var request = sessions.get(id)
    
      request.onsuccess = function(event) {
        // Get the old value that we want to update
        var data = event.target.result;
        
        // update the value(s) in the object that you want to change
        var oldPgsg = data.pgsg
        if (oldPgsg.slice == undefined){
          //a json object which we don't need to touch
          resolve();
          return;
        }
        var newPgsg = convertPgsg(oldPgsg)
        data.pgsg = JSON.parse(ba2str(newPgsg));
      
        // Put this updated object back into the database.
        var requestUpdate = sessions.put(data);
         requestUpdate.onerror = function(event) {
           // Do something with the error
           reject()
         };
         requestUpdate.onsuccess = function(event) {
           // Success - the data is updated!
           resolve();
         };
      };
      })
      await p;
  } 


}


function deleteSession(session) {
    return new Promise(function(resolve, reject) {
  
      let tx = db.transaction(['sessions'], 'readwrite');
      let sessions = tx.objectStore('sessions')
      var req = sessions.delete(session);
  
      req.onsuccess = function(event) {
        resolve()
      };
    }).
    then(function(){
      return new Promise(function(resolve, reject) {
  
        let tx = db_blobs.transaction(['sessions'], 'readwrite');
        let sessions = tx.objectStore('sessions')
        var req = sessions.delete(session);
    
        req.onsuccess = function(event) {
          resolve()
        };
      })
    })
  }


async function getAllSessions() {
return new Promise(function(resolve, reject) {

    console.log('begin db')
    let tx = db.transaction(['sessions'], 'readonly');
    let store = tx.objectStore('sessions');
    let req = store.getAll();

    req.onsuccess = function(event) {
    // The result of req.onsuccess is an array
    resolve(event.target.result)
    console.log('end db')
    }
    req.onerror = function(event) {
    alert('error in cursor request ' + event.target.errorCode);
    reject('error in cursor request ' + event.target.errorCode)
    }
})
}

  

async function createNewSession (creationTime, commonName, notaryName, cleartext, pgsg, is_imported){
    return new Promise(function(resolve, reject) {
      let tx = db.transaction(['sessions'], 'readwrite');
      let store = tx.objectStore('sessions');
      let was_imported = false;
      if (is_imported == true) was_imported = true;
      let entry = {creationTime: creationTime, sessionName: commonName,
        serverName:commonName, notaryName:notaryName, is_imported:was_imported};
      store.add(entry);
      tx.oncomplete = function() { 
        resolve();
      }
      tx.onerror = function(event) {
        alert('error storing note ' + event.target.errorCode);
        reject();
      }
    }).
    then(function(){
      return new Promise(function(resolve, reject) {
        let tx2 = db_blobs.transaction(['sessions'], 'readwrite');
        let store2 = tx2.objectStore('sessions');  
        //sessionName can be changed by the user in the manager window
        let entry2 = {creationTime: creationTime, serverName:commonName, cleartext:cleartext, pgsg:pgsg};
        store2.add(entry2); 
        tx2.oncomplete = function() { 
          resolve();
        }
        tx2.onerror = function(event) {
          alert('error storing note ' + event.target.errorCode);
          reject();
        }
      })
    })
  }

  
async function getSession(idx){
return new Promise(function(resolve, reject) {

    let tx = db.transaction(['sessions'], 'readonly');
    let store = tx.objectStore('sessions') 
    let req = store.get(idx);
    req.onsuccess = function(event) {
    let entry = event.target.result; 
    if (entry) {
        console.log(entry);
        resolve(entry)
    } else {
        console.log("entry 1 not found")
        resolve(null)
    }
    }
    req.onerror = function(event) {
    console.log('error getting entry 1 ' + event.target.errorCode);
    reject('error getting entry 1 ' + event.target.errorCode)
    }

})
}
  



//get data from blob store
async function getSessionBlob(idx){

    return new Promise(function(resolve, reject) {
  
     let tx = db_blobs.transaction(['sessions'], 'readonly');
     let store = tx.objectStore('sessions') 
     let req = store.get(idx);
     req.onsuccess = function(event) {
       let entry = event.target.result; 
       if (entry) {
         console.log(entry);
         resolve(entry)
       } else {
         console.log("note 1 not found")
         resolve(null)
       }
     }
     req.onerror = function(event) {
       console.log('error getting entry 1 ' + event.target.errorCode);
       reject('error getting entry 1 ' + event.target.errorCode)
     }
  
    })
  
  }


async function getPref(pref){
return new Promise(function(resolve, reject) {

    let tx = db.transaction(['preferences'], 'readonly');
    let store = tx.objectStore('preferences') 
    let req = store.get(pref);
    req.onsuccess = function(event) {
    let entry = event.target.result; 
    if (entry) {
        console.log(entry);
        resolve(entry.value)
    } else {
        console.log("entry 1 not found")
        resolve(null)
    }
    }
    req.onerror = function(event) {
    console.log('error getting entry 1 ' + event.target.errorCode);
    reject('error getting entry 1 ' + event.target.errorCode)
    }

})
}


function setPref(pref, newvalue) {
    return new Promise(function(resolve, reject) {
  
    let tx = db.transaction(['preferences'], 'readwrite');
    let store = tx.objectStore('preferences')
    var request = store.get(pref)
  
    request.onsuccess = function(event) {
      // Get the old value that we want to update
      var data = event.target.result;
      
      // update the value(s) in the object that you want to change
      data.value = newvalue;
    
      // Put this updated object back into the database.
      var requestUpdate = store.put(data);
       requestUpdate.onerror = function(event) {
         // Do something with the error
         reject()
       };
       requestUpdate.onsuccess = function(event) {
         // Success - the data is updated!
         resolve();
       };
    };
    })
  }




  function renameSession(id, newname) {
    return new Promise(function(resolve, reject) {
  
  
    console.log('about to rename');
    // Start a database transaction and get the notes object store
    let tx = db.transaction(['sessions'], 'readwrite');
    let sessions = tx.objectStore('sessions')
    var request = sessions.get(id)
  
    request.onsuccess = function(event) {
      // Get the old value that we want to update
      var data = event.target.result;
      
      // update the value(s) in the object that you want to change
      data.sessionName = newname;
    
      // Put this updated object back into the database.
      var requestUpdate = sessions.put(data);
       requestUpdate.onerror = function(event) {
         // Do something with the error
         reject()
       };
       requestUpdate.onsuccess = function(event) {
         // Success - the data is updated!
         resolve();
       };
    };
    })
  } 