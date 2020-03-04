<?php

namespace App\Http\Controllers;

//require __DIR__ . '/vendor/autoload.php';
use Illuminate\Http\Request;
use App\Http\Requests\RegisterFormRequest;
use App\User;
use JWTAuth;
use Auth;


class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('jwt', ['except' => ['login']]);
    }
    public function register(Request $request)
    {
            $user = new User;
            $user->email = $request->email;
            $user->password = bcrypt($request->password);
                try {
                    return 
                     response([
                        'status' => 'success',
                        'data' => $user
                    ], 200); 
                } catch (Exception $e) {
                    echo 'Caught exception: '. $e->getMessage() ."\n";
                }
        } 
        

        public function login(Request $request)
        {
            $credentials = request(['email', 'password']);
        
            if (!$token = auth('api')->attempt($credentials)) {
                return response()->json(['error' => 'Unauthorized'], 401);
            } else {
                return $this->respondWithToken($token);
            }
        }

        public function logout()
        {
            auth()->logout();
    
            return response()->json(['message' => 'Successfully logged out'],200);
        }

        protected function respondWithToken($token)
        {
            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => auth('api')->factory()->getTTL() * 60
            ]);
        }
        
}
