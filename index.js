var http = require('http');
var crypto = require('crypto');
var pmx = require('pmx');
var pm2 = require('pm2');
var util = require('util');
var spawn = require('child_process').spawn;
var async = require('async');
var vizion = require('vizion');
var ipaddr = require('ipaddr.js');

pmx.initModule({}, function (err, conf) {
  pm2.connect(function (err2) {
    if (err || err2) {
      console.error(err || err2);
      return process.exit(1);
    }
    // init the worker only if we can connect to pm2
    new Worker(conf).start();
  });
});

var Worker = function (opts) {
  if (!(this instanceof Worker)) {
    return new Worker(opts);
  }

  this.opts = opts;
  this.port = this.opts.port || 8888;
  this.apps = opts.apps || {};

  if (typeof (this.apps) !== 'object') {
    this.apps = JSON.parse(this.apps);
  }

  this.server = http.createServer(this._handleHttp.bind(this));
  return this;
};

Worker.prototype._handleHttp = function (req, res) {
  var self = this;

  // send instant answer since its useless to respond to the webhook
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.write('OK');

  // do something only with post request
  if (req.method !== 'POST') {
    res.end();
    return;
  }

  // get source ip
  req.ip = req.headers['x-forwarded-for'] || (req.connection ? req.connection.remoteAddress : false) ||
            (req.socket ? req.socket.remoteAddress : false) || ((req.connection && req.connection.socket)
              ? req.connection.socket.remoteAddress : false) || '';
  if (req.ip.indexOf('::ffff:') !== -1) {
    req.ip = req.ip.replace('::ffff:', '');
  }

  // get the whole body before processing
  req.body = '';
  req.on('data', function (data) {
    req.body += data;
  }).on('end', function () {
    self.processRequest(req);
  });

  res.end();
};

Worker.prototype.processRequest = function (req) {
  var targetName = reqToAppName(req);

  if (targetName.length === 0) return;

  var targetApp = this.apps[targetName];
  if (!targetApp) return;

  var error = this.checkRequest(targetApp, req);
  if (error) {
    console.log(error);
    return;
  }

  console.log('[%s] Received valid hook for app %s', new Date().toISOString(), targetName);

  var execOptions = {
    cwd: targetApp.cwd,
    env: process.env,
    shell: true
  };

  var phases = {
    resolveCWD: function resolveCWD(cb) {
      // if cwd is provided, we expect that it isnt a pm2 app
      if (targetApp.cwd) return cb();

      // try to get the cwd to execute it correctly
      pm2.describe(targetName, function (err, apps) {

        if (err || !apps || apps.length === 0) return cb(err || new Error('Application not found'));

        // execute the actual command in the cwd of the application
        execOptions.cwd = targetApp.cwd = apps[0].pm_cwd ? apps[0].pm_cwd : apps[0].pm2_env.pm_cwd;
        return cb();
      });
    },
    
    pullTheApplication: function pullTheApplication(cb) {
      vizion.update({
        folder: targetApp.cwd
      }, logCallback(cb, '[%s] Successfuly pulled application %s', new Date().toISOString(), targetName));
    },
    
    preHook: function preHook(cb) {
      if (!targetApp.prehook) return cb();
      spawnAsExec(targetApp.prehook, execOptions, logCallback(cb, '[%s] Prehook command has been successfuly executed for app %s', new Date().toISOString(), targetName));
    },

    reloadApplication: function reloadApplication(cb) {
      if (targetApp.nopm2) return cb();
      pm2.reload(targetName, logCallback(cb, '[%s] Successfuly reloaded application %s', new Date().toISOString(), targetName));
    },
    
    postHook: function postHook(cb) {
      if (!targetApp.posthook) return cb();
      // execute the actual command in the cwd of the application
      spawnAsExec(targetApp.posthook, execOptions, logCallback(cb, '[%s] Posthook command has been successfuly executed for app %s', new Date().toISOString(), targetName));
    }
  };
  async.series(Object.keys(phases).map(function(k){ return phases[k]; }),
    function (err, results) {
      if (err) {
        console.log('[%s] An error has occuring while processing app %s', new Date().toISOString(), targetName);
        if (targetApp.errorhook) spawnAsExec(targetApp.errorhook, execOptions,
          logCallback(() => {}, '[%s] Errorhook command has been successfuly executed for app %s', new Date().toISOString(), targetName));
        console.error(err);
      }
    });
};

Worker.prototype.checkRequest = function checkRequest(targetApp, req) {
  var targetName = reqToAppName(req);
  switch (targetApp.service) {
    case 'gitee': {
      if (!req.headers['x-gitee-token']) {
        return util.format('[%s] Received invalid request for app %s (no headers found)', new Date().toISOString(), targetName);
      }

      var timestamp = req.headers['x-gitee-timestamp']
      const stringToSign = timestamp + '\n' + targetApp.secret;
      const hmac = crypto.createHmac('sha256', targetApp.secret);
      hmac.update(stringToSign);
      const signature = hmac.digest('base64');

      if (req.headers['x-gitee-token'] !== signature) {
        return util.format('[%s] Received invalid request for app %s (not matching secret)', new Date().toISOString(), targetName);
      }
      break;
    }
    case 'gitlab': {
      if (!req.headers['x-gitlab-token']) {
        return util.format('[%s] Received invalid request for app %s (no headers found)', new Date().toISOString(), targetName);
      }

      if (req.headers['x-gitlab-token'] !== targetApp.secret) {
        return util.format('[%s] Received invalid request for app %s (not matching secret)', new Date().toISOString(), targetName);
      }
      break;
    }
    case 'jenkins': {
      // ip must match the secret
      if (req.ip.indexOf(targetApp.secret) < 0) {
        return util.format('[%s] Received request from %s for app %s but ip configured was %s', new Date().toISOString(), req.ip, targetName, targetApp.secret);
      }

      var body = JSON.parse(req.body);
      if (body.build.status !== 'SUCCESS') {
        return util.format('[%s] Received valid hook but with failure build for app %s', new Date().toISOString(), targetName);
      }
      if (targetApp.branch && body.build.scm.branch.indexOf(targetApp.branch) < 0) {
        return util.format('[%s] Received valid hook but with a branch %s than configured for app %s', new Date().toISOString(), body.build.scm.branch, targetName);
      }
      break;
    }
    case 'droneci': {
      // Authorization header must match configured secret
      if (!req.headers['Authorization']) {
        return util.format('[%s] Received invalid request for app %s (no headers found)', new Date().toISOString(), targetName);
      }
      if (req.headers['Authorization'] !== targetApp.secret) {
        return util.format('[%s] Received request from %s for app %s but incorrect secret', new Date().toISOString(), req.ip, targetName);
      }

      var data = JSON.parse(req.body);
      if (data.build.status !== 'SUCCESS') {
        return util.format('[%s] Received valid hook but with failure build for app %s', new Date().toISOString(), targetName);
      }
      if (targetApp.branch && data.build.branch.indexOf(targetApp.branch) < 0) {
        return util.format('[%s] Received valid hook but with a branch %s than configured for app %s', new Date().toISOString(), data.build.branch, targetName);
      }
      break;
    }
    case 'bitbucket': {
      var tmp = JSON.parse(req.body);
      var ip = targetApp.secret || '104.192.143.0/24';
      var configured = ipaddr.parseCIDR(ip);
      var source = ipaddr.parse(req.ip);

      if (!source.match(configured)) {
        return util.format('[%s] Received request from %s for app %s but ip configured was %s', new Date().toISOString(), req.ip, targetName, ip);
      }
      if (!tmp.push) {
        return util.format("[%s] Received valid hook but without 'push' data for app %s", new Date().toISOString(), targetName);
      }
      if (targetApp.branch && tmp.push.changes[0] && tmp.push.changes[0].new.name.indexOf(targetApp.branch) < 0) {
        return util.format('[%s] Received valid hook but with a branch %s than configured for app %s', new Date().toISOString(), tmp.push.changes[0].new.name, targetName);
      }
      break;
    }
    case 'gogs': {
      if (!req.headers['x-gogs-event'] || !req.headers['x-gogs-signature']) {
        return util.format('[%s] Received invalid request for app %s (no headers found)', new Date().toISOString(), targetName);
      }

      // compute hash of body with secret, github should send this to verify authenticity
      var temp = crypto.createHmac('sha256', targetApp.secret);
      temp.update(req.body, 'utf-8');
      var hash = temp.digest('hex');

      if (hash !== req.headers['x-gogs-signature']) {
        return util.format('[%s] Received invalid request for app %s', new Date().toISOString(), targetName);
      }

      var body = JSON.parse(req.body)
      if (targetApp.branch) {
        var regex = new RegExp('/refs/heads/' + targetApp.branch)
        if (!regex.test(body.ref)) {
          return util.format('[%s] Received valid hook but with a branch %s than configured for app %s', new Date().toISOString(), body.ref, targetName);
        }
      }
      break;
    }
    case 'github' :
    default: {
      if (!req.headers['x-github-event'] || !req.headers['x-hub-signature']) {
        return util.format('[%s] Received invalid request for app %s (no headers found)', new Date().toISOString(), targetName);
      }

      // compute hash of body with secret, github should send this to verify authenticity
      var temp = crypto.createHmac('sha1', targetApp.secret);
      temp.update(req.body, 'utf-8');
      var hash = temp.digest('hex');

      if ('sha1=' + hash !== req.headers['x-hub-signature']) {
        return util.format('[%s] Received invalid request for app %s', new Date().toISOString(), targetName);
      }

      var body = JSON.parse(req.body)
      if (targetApp.branch) {
        var regex = new RegExp('/refs/heads/' + targetApp.branch)
        if (!regex.test(body.ref)) {
          return util.format('[%s] Received valid hook but with a branch %s than configured for app %s', new Date().toISOString(), body.ref, targetName);
        }
      }
      break;
    }
  }
  return false;
};

Worker.prototype.start = function () {
  var self = this;
  this.server.listen(this.opts.port, function () {
    console.log('Server is ready and listen on port %s', self.port);
  });
};

function logCallback(cb, message) {
  var wrappedArgs = Array.prototype.slice.call(arguments);
  return function (err, data) {
    if (err) return cb(err);

    wrappedArgs.shift();
    console.log.apply(console, wrappedArgs);
    cb();
  }
}

function reqToAppName(req) {
  var targetName = null;
  try {
    targetName = req.url.match(/\/([^/?]+)\??/)[1];
  } catch (e) {}
  return targetName || null;
}

function spawnAsExec(command, options, cb) {
  var child = spawn('eval', [command], options);

  child.stdout.on('data', (data) => {
    console.log(`stdout: ${data}`);
  });
  
  child.stderr.on('data', (data) => {
    console.error(`stderr: ${data}`);
  });

  child.on('error', (err) => {
    console.error('err', err);
  });

  child.on('close', cb);
}
