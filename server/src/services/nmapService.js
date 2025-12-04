const { exec } = require('child_process');
const xml2js = require('xml2js');

exports.scanHost = (ip) => {
  return new Promise((resolve, reject) => {
    const cmd = `nmap -sn -oX - ${ip}`;
    exec(cmd, { maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      if (err) return reject(err);
      // parse xml to json for easier storage
      xml2js.parseString(stdout, { explicitArray: false }, (err2, parsed) => {
        if (err2) return resolve({ raw: stdout }); // return raw if parse fails
        resolve({ xml: parsed, raw: stdout });
      });
    });
  });
};
