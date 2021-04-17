function Login() {
	let login = document.getElementById("login").value;
	let password = document.getElementById("password").value;
	
	loginReq(login, password)
}

var SID="-1";

async function loginReq(login, password) {
	let res = await fetch("http://localhost:8080/login", {
		method: 'POST', // *GET, POST, PUT, DELETE, etc.
		mode: 'cors', // no-cors, *cors, same-origin
		cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
		credentials: 'same-origin', // include, *same-origin, omit
		headers: {
		  'Content-Type': 'application/json'
		  // 'Content-Type': 'application/x-www-form-urlencoded',
		},
		redirect: 'follow', // manual, *follow, error
		referrerPolicy: 'no-referrer', // no-referrer, *client
		body: '{"login":"'+login+'","password":"'+password+'"}'// body data type must match "Content-Type" header
	  });
	let inf = await res;
	console.log(inf);
	
	let jso = await res.text();
	if (jso=="unknown") {
		document.getElementById("auth").innerHTML = "Incorrect username or password";
	} else {
		document.getElementById("auth").innerHTML = "";
		SID = jso;
	}
}

function pop() {
	getReq();
}

async function getReq() {
	let res = await fetch("http://localhost:8080/data", {
		method: 'GET', // *GET, POST, PUT, DELETE, etc.
		mode: 'cors', // no-cors, *cors, same-origin
		cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
		credentials: 'same-origin', // include, *same-origin, omit
		headers: {
		  'Content-Type': 'application/json',
		  'Session-ID': SID
		  // 'Content-Type': 'application/x-www-form-urlencoded',
		},
		redirect: 'follow', // manual, *follow, error
		referrerPolicy: 'no-referrer', // no-referrer, *client
	  });
	let inf = await res;
	console.log(inf);
	
	let jso = await res.text();
	if (jso == "success") {
		document.getElementById("resp").innerHTML = "You gained access to data";
	} else {
		document.getElementById("resp").innerHTML = "Unauthorized";
	}
}
