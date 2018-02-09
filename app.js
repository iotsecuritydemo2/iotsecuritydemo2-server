/*eslint-env node*/

//------------------------------------------------------------------------------
// node.js starter application for Bluemix
//------------------------------------------------------------------------------

// This application uses express as its web server
// for more info, see: http://expressjs.com
const express = require('express');
//const morgan = require('morgan');
//const log4js = require("log4js");
//const logger = log4js.getLogger("iotsecuritydemo2");

// cfenv provides access to your Cloud Foundry environment
// for more info, see: https://www.npmjs.com/package/cfenv
const cfenv = require('cfenv');

// create a new express server
const app = express();

// serve the files out of ./public as our main files
app.use(express.static(__dirname + '/public'));
//app.use(morgan('dev')); // New Express 4 logger


// get the app environment from Cloud Foundry
var appEnv = cfenv.getAppEnv();

//if(! process.env.VCAP_APPLICATION)
//	console.warn('VCAP_APPLICATION environment variable not found, using defaults.');
//else
//	console.log("VCAP_APPLICATION=\n"+process.env.VCAP_APPLICATION);

var vcapServices;

if(! process.env.VCAP_SERVICES) {
	console.error('VCAP_SERVICES environment variable is required. Are you running this on Bluemix?');
	process.exit();
}

var DEFAULT_MAX_EVENTS_RETRIEVED = 10;

//------------ Prepare for encryption/ decryption -----------------

var crypto = require('crypto');
var algorithm = 'aes-256-ctr';
var cryptoKey = 'd6F3Efeq';

function encrypt(text){
  var cipher = crypto.createCipher(algorithm, cryptoKey);
  var crypted = cipher.update(text,'utf8','hex');
  crypted += cipher.final('hex');
  return crypted;
}
 
function decrypt(text){
  var decipher = crypto.createDecipher(algorithm, cryptoKey);
  var dec = decipher.update(text,'hex','utf8');
  dec += decipher.final('utf8');
  return dec;
}
 
//------------ Prepare the Cloudant DB -----------------

const dbCredentials = {
		dbName : 'iotsecuritydemo',
		host : 		vcapServices["cloudantNoSQLDB"][0].credentials.host,
		port : 		vcapServices["cloudantNoSQLDB"][0].credentials.port,
		user : 		vcapServices["cloudantNoSQLDB"][0].credentials.username,
		password : 	vcapServices["cloudantNoSQLDB"][0].credentials.password,
		url : 		vcapServices["cloudantNoSQLDB"][0].credentials.url
	};

const cloudant = require('cloudant')(dbCredentials.url);
var db;

function charArrayToString(a) {
	var s = '';
	var i = 0; 
	while(i < a.length)
		s += String.fromCharCode(a[i++]);
	return s;
}

function initDBConnection() {
	//var vcapServices = JSON.parse(vcap_services);
	
	// check if DB exists if not create
	cloudant.db.create(dbCredentials.dbName, function (err, res) {
		if (err) { 
			if(err.statusCode == 412)
				console.log('Using existing db.');
			else
				console.log('Could not create db ', err); 
		}
		else
			console.log('Created db.');
	});
	
	db = cloudant.use(dbCredentials.dbName);
	
	if(db == null){
		console.warn('Could not connect to the db. Data will be unavailable to the UI.');
	}

	var recDeviceIndex = 
		{
		  "index": {
			"fields": [
			  "recordType",
			  "deviceId"
		    ]
		  },
		  "type": "json"
		};
	
	db.index(recDeviceIndex, function(err, response) {
		if(err) 
			console.log("Error creating index: "+JSON.stringify(err, null, 4));
		if(response)
			console.log("Response creating index: "+JSON.stringify(response, null, 4));
	});

	var recTsIndex = 
		{
		  "index": {
			"fields": [
			  "timestamp"
		    ]
		  },
		  "type": "json"
		};

	db.index(recTsIndex, function(err, response) {
		if(err) 
			console.log("Error creating index: "+JSON.stringify(err, null, 4));
		if(response)
			console.log("Response creating index: "+JSON.stringify(response, null, 4));
	});

	var recUserIndex = 
		{
		  "index": {
			"fields": [
			  "recordType",
			  "userId"
		    ]
		  },
		  "type": "json"
		};

	db.index(recUserIndex, function(err, response) {
		if(err) 
			console.log("Error creating index: "+JSON.stringify(err, null, 4));
		if(response)
			console.log("Response creating index: "+JSON.stringify(response, null, 4));
	});

	var recUserGroupIndex = 
	{
	  "index": {
		"fields": [
		  "recordType",
		  "groupName"
	    ]
	  },
	  "type": "json"
	};

	db.index(recUserGroupIndex, function(err, response) {
		if(err) 
			console.log("Error creating index: "+JSON.stringify(err, null, 4));
		if(response)
			console.log("Response creating index: "+JSON.stringify(response, null, 4));
	});
} // end initDBConnection()


function stringify(doc) {
	var payload = JSON.parse(
			(typeof doc.payload == 'string' ? 
					decrypt(doc.payload) : 
					charArrayToString(doc.payload.data)));
	
	var result = '{' +
		'"_id":"'+ doc._id + '"' +
		', "_rev":"'+ doc._rev + '"' +
		', "recordType":"'+ doc.recordType + '"' +
		', "deviceType":"'+ doc.deviceType + '"' +
		', "deviceId":"'+ doc.deviceId + '"' +
		', "eventType":"'+ doc.eventType + '"' +
		', "format":"'+ doc.format + '"' +
		', "timestamp":"'+ doc.timestamp + '"' +
		', "payload":'+ JSON.stringify(payload) +
	'}';

	return result;
}

function findUser(userId, callback) {
	var query = { selector: { 'recordType': 'user', 'userId': userId } };

	console.log('Querying db: '+JSON.stringify(query, null, 4));
	
	db.find(query, callback);
}

function findUserGroup(groupName, callback) {
	var query = { selector: { 'recordType': 'userGroup', 'groupName': groupName } };

	console.log('Querying db: '+JSON.stringify(query, null, 4));
	
	db.find(query, callback);
}

function findDeviceList(userGroup, callback) {
	var query;
	
	if(userGroup.roleAdmin == 'true')
		query = { selector: { 'recordType': 'status' } };
	else
		query = { selector: { 'recordType': 'status', 'deviceId': {'$in': userGroup.devices} } };
	
	console.log('Querying db: '+JSON.stringify(query, null, 4));
	
	db.find(query, callback);
}

function getDevice(deviceId, callback) {
	var query = { 
			'selector': { 'recordType': 'status', 'deviceId': deviceId }
		};

	db.find(query, callback);
}

function getDeviceEvents(deviceId, nofRecords, callback) {
	var query = { 
					"selector": { "recordType": "event", "deviceId": deviceId }, 
					"sort": [{"recordType": "desc"}, {"timestamp": "desc"}],
					"limit": nofRecords 
				};
	
	db.find(query, function(error, record) {
		var result;
		
		if(! error) {
			result = '{"docs": ['; 
			
			var index = 0;
			
			console.log("No of events retrieved from db for device '"+deviceId+"' is: "+record.docs.length);
			
			if(index < record.docs.length && index < nofRecords) {
				result += stringify(record.docs[index]);
				index++;
				
				while(index < record.docs.length) {
					result += ', ' + stringify(record.docs[index]);
					index++;
				}
			}
			
			result += ']}';

			//console.log("Device list: "+result);
		}
		callback(error, result);
	});
}

function insertEventToDB(deviceType, deviceId, eventType, format, payload) {
	var encryptedPayload = encrypt(payload);
	
	// --- Insert the event record
		
	db.insert({
			"recordType" : "event",
			"deviceType" : deviceType,
			"deviceId" : deviceId,
			"eventType" : eventType,
			"format" : format,
			"timestamp" : JSON.parse(payload).timestampMillis,
			"payload" : encryptedPayload
		}, 
		'', // Generate id
		function(err, doc) {
			if(err) {
				console.log("Error creating event record: "+err);
			}
			if(doc) {
				console.log("Inserted: " + JSON.stringify(doc, null, 4));
				
				db.get(doc.id, function(err, record) {
						if(record) {
							var decryptedPayload = decrypt(record.payload);
							console.log("Decrypted payload: "+decryptedPayload);
						}  
					});
			}
		}
	);	
}

function insertStatusToDB(deviceType, deviceId, payload, topic) {
	// --- Insert the status record
	
	db.update({
			"recordType" : "status",
			"deviceType" : deviceType,
			"deviceId" : deviceId,
			"topic" : topic,
			"timestamp" : Date.parse(payload.Time),
			"payload" : encrypt(payload)
		}, 
		deviceId, // Generate id
		function(err, doc) {
			if(err) {
				console.log("Error creating/updating status record: "+JSON.stringify(err, null, 4));
			}
		}
	);	
}

function executeIfAllowed(user, deviceId, access, callback) {
	var userJson = JSON.stringify(user, null, 4);
	console.log('Calling user is: '+userJson);
	
	if('{}' == userJson) {
		callback(new Error("No user information provided in request."), null);
		return;
	}
	if(! user.identities) {
		callback(new Error("User information does not have 'identities' attribute."), null);
		return;
	}
	if(! user.identities[0].id) {
		callback(new Error("User information does not have 'id' in 'identities' array."), null);
		return;
	}
		
	findUser(user.identities[0].id, function(error, userInfoDocs) {
		if(error) {
			callback(error, null);
			return;
		}
		var userInfo = userInfoDocs.docs[0];
		
		console.log('Found user info in db:'+JSON.stringify(userInfo, null, 4));
		
		if(! userInfo.attributes) {
			callback(new Error("User record in db does not have 'attributes' field."), null);
			return;
		}
		if(! userInfo.attributes.userGroup) {
			callback(new Error("User 'attributes' field in db do not have user group."), null);
			return;
		}
		
		findUserGroup(userInfo.attributes.userGroup, function(error, userGroupDocs) {
			if(error) {
				callback(error, null);
				return;
			}
			var userGroup = userGroupDocs.docs[0];
			
			console.log('User group is: '+JSON.stringify(userGroup, null, 4));
			
			if(userGroup.roleAdmin == 'true')
				callback(null, userGroup);
			else if((deviceId != '') && (userGroup.devices.indexOf(deviceId) < 0))
				callback(new Error("User not authorized for this device."), userGroup);
			else if((access == 'reader') && (userGroup.roleReader != 'true'))
				callback(new Error("User not authorized to access data of any device."), userGroup);
			else if((access == 'writer') && (userGroup.roleWriter != 'true'))
				callback(new Error("User not authorized to send command to any device."), userGroup);
			else
				callback(null, userGroup);
		});
	});	
} // end executeIfAllowed

//------------ Connect to the db ----------------
initDBConnection();

var MAX_UPDATE_RETRY = 3;

db._update = function(obj, key, retry, callback) {
	if(retry > MAX_UPDATE_RETRY) {
		callback(new Error("Max update retries exceeded."), null);
		return;
	}
	
	var db = this;
	db.get(key, function (error, existing) { 
		if(!error) obj._rev = existing._rev;
		db.insert(obj, key, function(error, result) {
			if(error) {
				if(error.statusCode == 409)
					db._update(obj, key, retry+1, callback);
				else
					callback(error, null);
			}
		});
	});
}

db.update = function(obj, key, callback) {
	db._update(obj, key, 1, callback);
}

//------------ End of Cloudant DB related methods -----------------

//------------ Prepare to connect to IoTF -----------------

const IotfClient = require("ibmiotf").IotfApplication;

const vcapServicesIotfServiceList = vcapServices["iotf-service"];

var org 			= vcapServices["iotf-service"][0].credentials.org;
var apiKey 		= vcapServices["iotf-service"][0].credentials.apiKey;
var apiToken 	= vcapServices["iotf-service"][0].credentials.apiToken;

var iotConfig = {
	    "org" : org,
	    "id" : "iotsecuritydemo",
	    "type" : "shared",
	    "auth-key" : apiKey,
	    "auth-token" : apiToken
	};

var iotfClient = new IotfClient(iotConfig);

iotfClient.connect();

iotfClient.on("error", function (err) {
    console.log("IoTF client error: "+err);
});

iotfClient.on("connect", function () {
	// Subscribe to status from all devices
	iotfClient.subscribeToDeviceStatus();
		
	// Subscribe to all events from all devices
    	iotfClient.subscribeToDeviceEvents();
});

iotfClient.on("deviceEvent", function (deviceType, deviceId, eventType, format, payload) {
	// Handle events from devices
    console.log("Device Event from :: "+deviceType+" : "+deviceId+" of event "+eventType+" with payload : "+payload);
    //console.log("Device Event from :: "+deviceType+" : "+deviceId+" of event "+eventType);
    
    insertEventToDB(deviceType, deviceId, eventType, format, payload);
});

iotfClient.on("deviceStatus", function (deviceType, deviceId, payload, topic) {
	// Handle status updates from devices
    console.log("Device status from :: "+deviceType+" : "+deviceId+" with payload : "+payload);
    
    insertStatusToDB(deviceType, deviceId, payload, topic);
});

function sendCommandToDevice(deviceId, command, data) {
	if(iotfClient.isConnected)
		getDevice(deviceId, function(error, deviceStatus) {
			if(error) 
				throw error;
			else
				iotfClient.publishDeviceCommand(deviceStatus.deviceType, deviceId, command, "json", data);
		});
	else
		throw new Error("Not connected to IoT Platform.");
}

//------------ End of IoT Platform related methods -----------------

// ----------- Protecting backend APIs with AppID service ----------

const APIStrategy = require('bluemix-appid').APIStrategy;
const passport = require("passport");

//Configure passportjs to use APIStrategy - it will by default pick up from VCAP_SERVICES
if(process.env.VCAP_SERVICES)
	passport.use(new APIStrategy());
else {
	passport.use(new APIStrategy({
		tenantId: 		vcapServices["AppID"][0].credentials.tenantId,
		clientId: 		vcapServices["AppID"][0].credentials.clientId,
		secret: 			vcapServices["AppID"][0].credentials.secret,
		oauthServerUrl: vcapServices["AppID"][0].credentials.oauthServerUrl
	}));
}

//Configure express application to use passportjs
app.use(passport.initialize());
app.use(passport.session());

// Configure passportjs with user serialization/deserialization. This is required
// for authenticated session persistence accross HTTP requests. See passportjs docs
// for additional information http://passportjs.org/docs
passport.serializeUser(function(user, cb) {
	cb(null, user);
});

passport.deserializeUser(function(obj, cb) {
	cb(null, obj);
});

//------------ The custom API routes -----------------

const iotRouteBase = '/iotf';

app.get(iotRouteBase + '/devices', 
	passport.authenticate(APIStrategy.STRATEGY_NAME, {session: true}), 
	function(req, res) {
	    	console.log(iotRouteBase+'/devices entered.');
	    	console.log("Request headers: ", JSON.stringify(req.headers, null, 4));
	    		
		// Check for the user group and filter out the devices that the user does not have access to
		executeIfAllowed(req.user, '', 'reader', function(error, userGroup) {
			if(error) {
				console.log('Error: '+JSON.stringify(error, null, 4));
				res.status(400).json(error);
			}
			else {
				console.log('Returning device list: ', userGroup.devices);
				res.status(200).json(userGroup.devices);
				/**
				findDeviceList(userGroup, function(error, deviceListDocs) {
					if(error) {
						console.log('Error: '+JSON.stringify(error, null, 4));
						res.status(400).json(error);
					}
					else {
						console.log('Returning device list: ', deviceListDocs);
						res.status(200).send(deviceListDocs);
					}
				});
				**/
			}
		});
	}
);

app.get(iotRouteBase + '/devices/:id', 
	passport.authenticate(APIStrategy.STRATEGY_NAME, {session: true}), 
	function(req, res) {
		console.log(iotRouteBase+'/devices/id entered.');
    		console.log("Security context: ", req.securityContext);
    		
			// Check for the user authorization for the device and reject as necessary
			console.log('Calling user is: '+JSON.stringify(req.user, null, 4));

			// If neither 'cmd' nor 'count' is present in req parameters, then assume default count
			var count = DEFAULT_MAX_EVENTS_RETRIEVED;
			var command = '';
			var commandData = '';

			// Check if 'cmd' parameter is present in request to send command to IoT device
			if(req.query.cmd) {
				command = req.query.cmd;
				
				if(req.query.data)
					commandData = req.query.data;
				
				console.log(
						'Sending command to device with id: '+req.params.id+
						', command: '+command+', data: '+commandData);
		
				executeIfAllowed(req.user, req.params.id, 'writer', function(error, userGroup) {
					if(error) {
						console.log('Error: '+JSON.stringify(error, null, 4));
						res.status(400).json(error);
					}
					else {
						try {
							sendCommandToDevice(req.params.id, command, commandData);
							
							res.setHeader('Content-Type', 'application/json');
							res.status(200).send('{ "status": "Published command to device"}');
						}
						catch(err) {
							res.status(400).json(err);
						}
					}
				});
				
				return;
			}
			// Check if 'count' parameter is present in request to retrieve IoT device data
			else if(req.query.count) {
				count = parseInt(req.query.count, 10); 
			}
				
			console.log('Querying device with id: '+req.params.id+', count: '+count);

			executeIfAllowed(req.user, req.params.id, 'reader', function(error, userGroup) { 
				if(error)
					res.status(400).json(error);
				else {
					getDeviceEvents(req.params.id, count, function(error, result) {
						if(error)
							res.status(400).json(error);
						else {
							console.log('Returning device data: '+result);
							res.setHeader('Content-Type', 'application/json');
							res.status(200).send(result);
						}
					});
				}
			}); 
		}
);


//----------- End of backend APIs with AppID service ----------


// start server on the specified port and binding host
app.listen(appEnv.port, '0.0.0.0', function() {
  // print a message when the server starts listening
  console.log("Server starting on " + appEnv.url);
});
