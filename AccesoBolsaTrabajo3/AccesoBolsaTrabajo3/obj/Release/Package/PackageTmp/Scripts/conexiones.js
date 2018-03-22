function GuardarProblema() {
    var Email = $("#email").val();
    var Commentary = $("#commentary").val();


    $.ajax({
        type: "POST",
        url: "/AccesoBolsaTrabajo3/Account/ReportarProblema",
        dataType: "json",
        data: {
            Email: Email,
            Commentary: Commentary,
        },
        success: function (resultado) {

            // successmessage = 'Data was succesfully captured';
            alert("enviado su error");

        }, error: function (e) { alert("Ocurrio un error"); }
    });
}