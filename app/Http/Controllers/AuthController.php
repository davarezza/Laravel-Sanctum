<?php

namespace App\Http\Controllers;

use App\Models\Role;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function registerUser(Request $request)
    {
        $dataUser = new User();
        $rules = [
            'name' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required',
        ];

        $validator = Validator::make($request->all(), $rules);
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => 'Proses validasi gagal',
                'data' => $validator->errors()
            ], 401);
        }

        $dataUser->name = $request->name;
        $dataUser->email = $request->email;
        $dataUser->password = Hash::make($request->password);
        $dataUser->save();

        return response()->json([
            'status' => true,
            'message' => 'Berhasil menambah user baru'
        ], 200);
    }

    public function loginUser(Request $request)
    {
        $rules = [
            'email' => 'required|email',
            'password' => 'required',
        ];

        $validator = Validator::make($request->all(), $rules);
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => 'Proses login gagal',
                'data' => $validator->errors()
            ], 401);
        }

        if (!Auth::attempt($request->only(['email', 'password']))) {
            return response()->json([
                'status' => false,
                'message' => 'Email dan Password salah'
            ], 401);
        }

        $dataUser = User::where('email',$request->email)->first();
        $role = Role::join("user_role","user_role.role_id","=","roles.id")
                ->join("users","users.id","=","user_role.user_id")
                ->where('user_id',$dataUser->id)
                ->pluck('roles.role_name')->toArray();
            if (empty($role)) {
                $role = ["*"];
            }

        return response()->json([
            'status' => true,
            'message' => 'Berhasil login',
            'token' => $dataUser->createToken('api-product', $role)->plainTextToken
        ]);
    }
}
