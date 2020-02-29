function callExcel() {
  fetch("/getexcel");
}

document.getElementById("databutton").addEventListener("click", callExcel);
