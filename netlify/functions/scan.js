exports.handler = async function(event) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  const VT_KEY = '35d2db95ca66be371b3d67072de56fa9c1de18bfb6168df3bb7353805a50c19d';
  const { url, analysisId } = JSON.parse(event.body || '{}');

  try {
    if (analysisId) {
      const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': VT_KEY }
      });
      const data = await res.json();
      return { statusCode: 200, headers, body: JSON.stringify(data) };
    }

    if (url) {
      const urlId = Buffer.from(url).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
      const lookupRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { 'x-apikey': VT_KEY }
      });
      if (lookupRes.ok) {
        const data = await lookupRes.json();
        if (data?.data?.attributes?.last_analysis_stats) {
          return { statusCode: 200, headers, body: JSON.stringify({ type: 'cached', data }) };
        }
      }
      const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': VT_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'url=' + encodeURIComponent(url)
      });
      const submitData = await submitRes.json();
      return { statusCode: 200, headers, body: JSON.stringify({ type: 'submitted', data: submitData }) };
    }

    return { statusCode: 400, headers, body: JSON.stringify({ error: 'No url provided' }) };
  } catch(err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};
