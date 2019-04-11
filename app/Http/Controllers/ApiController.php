<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterAuthRequest;
use App\User;
use Illuminate\Http\Request;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
class ApiController extends Controller
{
    public $loginAfterSignUp = true;

//    Accept RegisterAuthRequest. A user is created with the data present in the request.
// If the loginAfterSignUp property is true, it will log-in the user by calling the login method after registering.
// Otherwise, a successful response is returned with the user data.

    public function register(RegisterAuthRequest $request)
    {
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();

        if ($this->loginAfterSignUp) {
            return $this->login($request);
        }

        return response()->json([
            'success' => true,
            'data' => $user
        ], 200);
    }

//get a subset of the request only containing email and password.
// JWTAuth::attempt() is called with input as the argument and the response is saved in a variable.
// If false is returned from the attempt method, we return a failure response.
// Otherwise, a success response is returned.
    public function login(Request $request)
    {
        $input = $request->only('email', 'password');
        $jwt_token = null;

        if (!$jwt_token = JWTAuth::attempt($input)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid Email or Password',
            ], 401);
        }

        return response()->json([
            'success' => true,
            'token' => $jwt_token,
        ]);
    }

//    the request is validated that it contains the token field.
// The token is invalidated by calling the invalidate method and a successful response is returned.
// If the JWTException exception caught, a failure response is returned.
    public function logout(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User logged out successfully'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, the user cannot be logged out'
            ], 500);
        }
    }


//the request is validated that it contains the token field.
// Then the authenticate method is called which returns the authenticated user.
// Finally, the response with the user is returned.
    public function getAuthUser(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        $user = JWTAuth::authenticate($request->token);

        return response()->json(['user' => $user]);
    }
}
