async function callCSV() {
  let csv = "";
  await fetch("/getexcel")
    .then(res => res.json())
    .then(data =>
      data["data"].forEach(row => {
        csv += row.join(",") + "\r\n";
      })
    );
  var hiddenLink = document.createElement("a");
  hiddenLink.href = "data:text/csv;charset=utf-8," + encodeURI(csv);
  hiddenLink.target = "_blank";
  hiddenLink.download = "patientdata.csv";
  hiddenLink.click();
}

document.getElementById("databutton").addEventListener("click", callCSV);
