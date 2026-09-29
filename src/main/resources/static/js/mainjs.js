$(document).ready(function () {

    // =========================
    // LOGIN
    // =========================

    $("#Login").click(function (e) {

        e.preventDefault();

        const email = $("#email").val().trim();
        const password = $("#password").val();

        if (!email || !password) {
            $("#feedback")
                .removeClass("text-success")
                .addClass("text-danger")
                .text("Vui lòng nhập email và password.");

            return;
        }

        $.ajax({
            url: "/auth/login",
            type: "POST",
            contentType: "application/json",

            data: JSON.stringify({
                email: email,
                password: password
            }),

            success: function (response) {

                console.log("Login response:", response);

                // Lưu JWT
                localStorage.setItem("token", response.token);

                // Lưu thời gian hết hạn
                if (response.expiresIn) {
                    localStorage.setItem(
                        "expiresIn",
                        response.expiresIn
                    );
                }

                $("#feedback")
                    .removeClass("text-danger")
                    .addClass("text-success")
                    .text("Đăng nhập thành công!");

                // Chuyển sang Profile
                setTimeout(function () {
                    window.location.href = "/user/profile";
                }, 300);
            },

            error: function (xhr) {

                console.error("Login error:", xhr);

                let message = "Đăng nhập thất bại.";

                if (xhr.responseJSON) {
                    if (xhr.responseJSON.message) {
                        message = xhr.responseJSON.message;
                    }
                }

                $("#feedback")
                    .removeClass("text-success")
                    .addClass("text-danger")
                    .text(message);
            }
        });
    });


    // =========================
    // PROFILE
    // =========================

    if ($("#profile").length > 0) {

        const token = localStorage.getItem("token");

        console.log("Profile token:", token);

        if (!token) {
            window.location.href = "/login";
            return;
        }

        $.ajax({
            url: "/users/me",
            type: "GET",

            headers: {
                "Authorization": "Bearer " + token
            },

            success: function (user) {

                console.log("Current user:", user);

                $("#profile").text(user.fullName);
                $("#emailProfile").text(user.email);

                if (user.images) {
                    $("#images")
                        .attr("src", user.images)
                        .removeClass("d-none");
                }
            },

            error: function (xhr) {

                console.error(
                    "Get profile error:",
                    xhr.status,
                    xhr.responseText
                );

                if (xhr.status === 401 || xhr.status === 403) {

                    localStorage.removeItem("token");
                    localStorage.removeItem("expiresIn");

                    window.location.href = "/login";
                }
            }
        });
    }


    // =========================
    // LOGOUT
    // =========================

    $("#logout").click(function () {

        localStorage.removeItem("token");
        localStorage.removeItem("expiresIn");

        window.location.href = "/login";
    });

});