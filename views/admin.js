const drug_info = 'https://api.drugdecider.com/api/v1/druginfo/';
const se_update = 'https://admin.drugdecider.com/updatedata/';
const down_data = 'https://admin.drugdecider.com/getexcel/';
const cookie_update_api = 'https://admin.drugdecider.com/revalidatecookie';

var old_info = {};
var xhr = new XMLHttpRequest();
xhr.open('GET', drug_info, false);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.onreadystatechange = function() {
  if (xhr.readyState === 4 && xhr.status === 200) {
    old_info = JSON.parse(xhr.responseText);
  }
};
xhr.send();

const submit_but = document.getElementById('submit_data');
const down_but = document.getElementById('down_but');

const paliperidone_lock = document.getElementById('paliperidone_lock');
const paliperidone_d = document.getElementById('paliperidone_d');
const paliperidone_s = document.getElementById('paliperidone_s');
const paliperidone_link = document.getElementById('paliperidone_link');

const olanzapine_lock = document.getElementById('olanzapine_lock');
const olanzapine_d = document.getElementById('olanzapine_d');
const olanzapine_s = document.getElementById('olanzapine_s');
const olanzapine_link = document.getElementById('olanzapine_link');

const quetiapine_lock = document.getElementById('quetiapine_lock');
const quetiapine_d = document.getElementById('quetiapine_d');
const quetiapine_s = document.getElementById('quetiapine_s');
const quetiapine_link = document.getElementById('quetiapine_link');

const risperdal_consta_lock = document.getElementById('risperdal_consta_lock');
const risperdal_consta_d = document.getElementById('risperdal_consta_d');
const risperdal_consta_s = document.getElementById('risperdal_consta_s');
const risperdal_consta_link = document.getElementById('risperdal_consta_link');

const paliperidone_palmitate_lock = document.getElementById(
  'paliperidone_palmitate_lock'
);
const paliperidone_palmitate_d = document.getElementById(
  'paliperidone_palmitate_d'
);
const paliperidone_palmitate_s = document.getElementById(
  'paliperidone_palmitate_s'
);
const paliperidone_palmitate_link = document.getElementById(
  'paliperidone_palmitate_link'
);

///////////////////////////////////////////////// Load Data /////////////////////////////////////////////////

/* SET LINKS */
paliperidone_link.setAttribute('value', old_info['paliperidone'].link);
olanzapine_link.setAttribute('value', old_info['olanzapine'].link);
quetiapine_link.setAttribute('value', old_info['quetiapine'].link);
risperdal_consta_link.setAttribute('value', old_info['risperdal_consta'].link);
paliperidone_palmitate_link.setAttribute(
  'value',
  old_info['paliperidone_palmitate'].link
);

/* SET DESCRIPTIONS */
paliperidone_d.innerHTML = old_info['paliperidone'].description;
olanzapine_d.innerHTML = old_info['olanzapine'].description;
quetiapine_d.innerHTML = old_info['quetiapine'].description;
risperdal_consta_d.innerHTML = old_info['risperdal_consta'].description;
paliperidone_palmitate_d.innerHTML =
  old_info['paliperidone_palmitate'].description;

/* SET SIDE EFFECTS */
function generate_se_from_list(se_list) {
  var str = '';
  for (var i = 0; i < se_list.length; ++i) {
    if (se_list[i] != '') str += se_list[i] + '\n';
  }
  if (str.slice(-1) === '\n') {
    str = str.substring(0, str.length - 1);
  }
  return str;
}
paliperidone_s.innerHTML = generate_se_from_list(
  old_info['paliperidone'].side_effects
);
olanzapine_s.innerHTML = generate_se_from_list(
  old_info['olanzapine'].side_effects
);
quetiapine_s.innerHTML = generate_se_from_list(
  old_info['quetiapine'].side_effects
);
risperdal_consta_s.innerHTML = generate_se_from_list(
  old_info['risperdal_consta'].side_effects
);
paliperidone_palmitate_s.innerHTML = generate_se_from_list(
  old_info['paliperidone_palmitate'].side_effects
);

///////////////////////////////////////////////// Page Setup /////////////////////////////////////////////////

/* Locking Mech */

paliperidone_lock.addEventListener('change', event => {
  if (event.target.checked) {
    paliperidone_d.toggleAttribute('disabled');
    paliperidone_s.toggleAttribute('disabled');
    paliperidone_link.toggleAttribute('disabled');
  } else {
    paliperidone_d.toggleAttribute('disabled');
    paliperidone_s.toggleAttribute('disabled');
    paliperidone_link.toggleAttribute('disabled');
  }
});

olanzapine_lock.addEventListener('change', event => {
  if (event.target.checked) {
    olanzapine_d.toggleAttribute('disabled');
    olanzapine_s.toggleAttribute('disabled');
    olanzapine_link.toggleAttribute('disabled');
  } else {
    olanzapine_d.toggleAttribute('disabled');
    olanzapine_s.toggleAttribute('disabled');
    olanzapine_link.toggleAttribute('disabled');
  }
});

quetiapine_lock.addEventListener('change', event => {
  if (event.target.checked) {
    quetiapine_d.toggleAttribute('disabled');
    quetiapine_s.toggleAttribute('disabled');
    quetiapine_link.toggleAttribute('disabled');
  } else {
    quetiapine_d.toggleAttribute('disabled');
    quetiapine_s.toggleAttribute('disabled');
    quetiapine_link.toggleAttribute('disabled');
  }
});

risperdal_consta_lock.addEventListener('change', event => {
  if (event.target.checked) {
    risperdal_consta_d.toggleAttribute('disabled');
    risperdal_consta_s.toggleAttribute('disabled');
    risperdal_consta_link.toggleAttribute('disabled');
  } else {
    risperdal_consta_d.toggleAttribute('disabled');
    risperdal_consta_s.toggleAttribute('disabled');
    risperdal_consta_link.toggleAttribute('disabled');
  }
});

paliperidone_palmitate_lock.addEventListener('change', event => {
  if (event.target.checked) {
    paliperidone_palmitate_d.toggleAttribute('disabled');
    paliperidone_palmitate_s.toggleAttribute('disabled');
    paliperidone_palmitate_link.toggleAttribute('disabled');
  } else {
    paliperidone_palmitate_d.toggleAttribute('disabled');
    paliperidone_palmitate_s.toggleAttribute('disabled');
    paliperidone_palmitate_link.toggleAttribute('disabled');
  }
});

///
var cookie = '';
if (sessionStorage.getItem('dd_HMAC')) {
  cookie = sessionStorage.getItem('dd_HMAC');
} else {
  cookie = dd_HMAC_cookie;
}

///////////////////////////////////////////////// Data Sumbission /////////////////////////////////////////////////

submit_but.addEventListener('click', collectAndSendData);
function collectAndSendData() {
  if (
    !(
      confirm(
        'Are you sure you want to change the drug data on drugdecider.com?'
      ) && confirm('Please confirm once again...')
    )
  ) {
    return;
  }

  var new_data = {
    paliperidone: {
      link: paliperidone_link.value,
      description: paliperidone_d.value,
      side_effects: paliperidone_s.value,
    },
    olanzapine: {
      link: olanzapine_link.value,
      description: olanzapine_d.value,
      side_effects: olanzapine_s.value,
    },
    quetiapine: {
      link: quetiapine_link.value,
      description: quetiapine_d.value,
      side_effects: quetiapine_s.value,
    },
    risperdal_consta: {
      link: risperdal_consta_link.value,
      description: risperdal_consta_d.value,
      side_effects: risperdal_consta_s.value,
    },
    paliperidone_palmitate: {
      link: paliperidone_palmitate_link.value,
      description: paliperidone_palmitate_d.value,
      side_effects: paliperidone_palmitate_s.value,
    },
  };

  var xhr = new XMLHttpRequest();
  xhr.open('POST', se_update, false);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      alert('Done!');
      location.reload();
    } else if (
      xhr.readyState === 4 &&
      (xhr.status === 401 || xhr.status === 500)
    ) {
      alert('Your login session has timed out. Please log in again!');
      logout_user();
    }
  };
  xhr.send(
    JSON.stringify({
      cookie,
      data: new_data,
    })
  );
}

down_but.addEventListener('click', getdbdata);
function getdbdata() {
  let csv = '';
  var xhr = new XMLHttpRequest();
  xhr.open('POST', down_data, false);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      csv = JSON.parse(xhr.responseText).data;
    } else if (
      xhr.readyState === 4 &&
      (xhr.status === 401 || xhr.status === 500)
    ) {
      alert('An error has occured, please log back in!');
      logout_user();
    }
  };
  xhr.send(
    JSON.stringify({
      cookie,
    })
  );
  var hiddenLink = document.createElement('a');
  hiddenLink.href = 'data:text/csv;charset=utf-8,' + encodeURI(csv.data);
  hiddenLink.target = '_blank';
  hiddenLink.download = 'wsAssignments.csv';
  hiddenLink.click();
}

var cookieupdater = setInterval(update_cookie, 1000 * 60 * 15);

function update_cookie() {
  var xhr = new XMLHttpRequest();
  xhr.open('POST', cookie_update_api, false);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
      cookie = JSON.parse(xhr.responseText).cookie;
    } else if (
      xhr.readyState === 4 &&
      (xhr.status === 401 || xhr.status === 500)
    ) {
      alert('An error has occured, please log back in!');
      logout_user();
    }
  };
  xhr.send(
    JSON.stringify({
      cookie,
    })
  );
}

function logout_user() {
  var hiddenform = document.createElement('form');
  hiddenform.action = '/logout?_method=DELETE';
  hiddenform.method = 'POST';
  hiddenform.submit();
}
