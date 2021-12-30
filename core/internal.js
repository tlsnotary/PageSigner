// allows to access PageSigner's internal classes by exposing them to the
// extension's window global

import * as utils from './utils.js';
import * as indexeddb from './indexeddb.js';
import * as globals from './globals.js';
import * as Main from './Main.js';
import {OTSender} from './twopc/OTSender.js';
import {OTReceiver} from './twopc/OTReceiver.js';


window.PageSigner = {
  Main:Main,
  globals:globals,
  utils:utils,
  indexeddb:indexeddb,
  OTSender:OTSender,
  OTReceiver:OTReceiver};
