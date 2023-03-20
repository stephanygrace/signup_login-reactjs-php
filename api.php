<?php
include './classes/database.php';
include './classes/jwt.php';

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = explode('/', $uri);

$action = $uri[3];

$bearer_token = get_bearer_token();
$is_jwt_valid = isset($bearer_token) ? is_jwt_valid($bearer_token) : false;

$database = new Database();


if ($action === 'register') {
    // Receiving User Information and Registering them in the database.
    $rest_json = file_get_contents('php://input');
    $_POST = json_decode($rest_json, true);
    $user = [
        'name' => $_POST['name'],
        'lastname' => $_POST['lastname'],
        'username' => $_POST['username'],
        'password' => md5($_POST['password']),
        'email' => $_POST['email'],
        'status' => 0,
        'created_date' => date('Y-m-d H:i:s'),
    ];

    if ($user_id = $database->register($user)) {
        $user['id'] = $user_id;
        if ($code = $database->generateConfirmCode($user_id)) {
            // Send generated code by email to user
            $headers = ['alg' => 'HS256', 'typ' => 'JWT'];
            $payload = ['user' => $user];
            $jwt = generate_jwt($headers, $payload);
            return_json(['status' => $jwt]);
        }
    }
} elseif ($action === 'confirm') {
    // Receive the token and confirmation code from the user and confirm wether the code is valid or not.
    if ($is_jwt_valid) {
        $rest_json = file_get_contents('php://input');
        $_POST = json_decode($rest_json, true);
        $user_id = getPayload($bearer_token)->user->id;

        if ($database->confirmCode($user_id, $_POST['code'])) {
            if ($database->activeUser($user_id)) {
                return_json(['status' => 1]);
            }
        }
    }
} elseif ($action === 'login') {
    // Receiving User Information and Login them in the database.
    $rest_json = file_get_contents('php://input');
    $_POST = json_decode($rest_json, true);

    if (
        $user = $database->loginUser(
            $_POST['username'],
            md5($_POST['password'])
        )
    ) {
        $headers = ['alg' => 'HS256', 'typ' => 'JWT'];
        $payload = ['user' => $user];
        $jwt = generate_jwt($headers, $payload);
        return_json(['status' => $jwt]);
    }
} elseif ($action === 'reset') {
    // Receiving User Information and Reset their password.
    $rest_json = file_get_contents('php://input');
    $_POST = json_decode($rest_json, true);

    if ($user = $database->getUserByUsernameOrEmail($_POST['username'])) {
        $generated_password = uniqid(round(11111, 99999));
        $user['password'] = md5($generated_password);
        if ($database->updateUser($user)) {
            //send password ($generated_password value) to user by email
            return_json(['status' => 1]);
        }
    }
} elseif ($action === 'user') {
    // Returns the User Profile
    if ($is_jwt_valid) {
        $username = getPayload($bearer_token)->user->username;
        if ($user = $database->getUserByUsernameOrEmail($username)) {
            return_json(['status' => $user]);
        }
    }
}
return_json(['status' => 0]);

function return_json($arr)
{
    // Receives an array of data, converts them to JSON, and sends it to the user
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Headers: *');
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($arr);
    exit();
}