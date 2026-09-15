const token = "hardcoded-token-abcdef";

function renderMessage(message) {
    document.getElementById("output").innerHTML = message;
}

function runCode(input) {
    return eval(input);
}
