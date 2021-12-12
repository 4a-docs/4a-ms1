<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class UserController extends Controller
{
    public function authenticate(Request $request)
    {
        $credentials = $request->only('email', 'password');
        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 400);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }

        // $user = JWTAuth::parseToken()->authenticate();
        $user = JWTAuth::attempt($credentials);
        $userId = Auth::user()->id;
        $data = [
            'token' => $user,
            'id' => $userId
        ];
        return response()->json($data, 200);
        // return response()->json(compact('token'));
    }

    public function getAuthenticatedUser(User $user)
    {
        return response()->json([
            'id' => $user->id,
            'name' => $user->name,
            'last_name' => $user->last_name,
            'email' => $user->email,
            'eps' => $user->eps,
            'identification' => $user->identification,
            'birthdate' => $user->birthdate,
            'phone' => $user->phone,
            'role' => $user->roles[0]['name']
        ]);
        // return response()->json(compact('user'));
    }

    public function getTokenAuthenticatedUser()
    {
        try {
            if (!$user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user_not_found'], 404);
            }
        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['token_expired'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['token_invalid'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['token_absent'], $e->getStatusCode());
        }
        $token = JWTAuth::parseToken()->authenticate();
        $role = $token->getRoleNames();
        $user = [
            'id' => $token->id,
            'name' => $token->name,
            'last_name' => $token->last_name,
            'email' => $token->email,
            'role' => $token->roles[0]['name']
        ];
        return response()->json($user, 200);
    }


    public function register(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:40',
            'last_name' => 'required|string|max:40',
            'phone' => 'required|string|max:20',
            'eps' => 'required|string|max:40',
            'identification' => 'required|string|max:15',
            'birthdate' => 'required|date',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create([
            'name' => $request->get('name'),
            'last_name' => $request->get('last_name'),
            'phone' => $request->get('phone'),
            'eps' => $request->get('eps'),
            'identification' => $request->get('identification'),
            'birthdate' => $request->get('birthdate'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ])->assignRole('patient');

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'id' => $user->id,
            'name' => $user->name,
            'last_name' => $user->last_name,
            'phone' => $user->phone,
            'eps' => $user->eps,
            'identification' => $user->identification,
            'birthdate' => $user->birthdate,
            'email' => $user->email, 
            'role' => $user->roles[0]['name'], 
            'token' => $token, 
        ], 201);
    }

    public function logout() {
        Auth::guard('api')->logout();
    
        return response()->json([
            'status' => 'success',
            'message' => 'logout'
        ], 200);
    }
}
