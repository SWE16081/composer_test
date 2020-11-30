<?php
namespace App\Http\Middleware;

use App\Exceptions\MyException;
use App\Exceptions\RefreshException;
use App\tools\ApiMessage;
use Closure;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenBlacklistedException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;
use Illuminate\Support\Facades\Log;

// 注意，这里要继承的是 jwt 的 BaseMiddleware
class JwtRefreshToken extends BaseMiddleware
{
    use ApiMessage;
    /**
     * Handle an incoming request.
     * @param  \Illuminate\Http\Request $request
     * @param  \Closure $next
     * @throws \Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException
     *
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        //检查请求中是否存在token
//         $this->checkForToken($request);
        if (! $this->auth->parser()->setRequest($request)->hasToken()) {
            throw new MyException('请求未携带token');
        }
        //认证token合法性
        try {
            // 检测用户的登录状态，如果正常则通过
            if ($this->auth->parseToken()->authenticate()) {
                return $next($request);
            }
        }catch (TokenBlacklistedException $exception){
            //反之用户登出之后 还拿着之前的token 登出的token是存于黑名单
            return $this->fail('黑名单的token,无法使用,请重新登录','',402);
        } catch (TokenExpiredException $exception) {
            //捕获到token过期的异常，刷新该用户的 token 并将它添加到响应头中
            try {
                // 刷新用户的 token
                $token = $this->auth->refresh();
                // 在响应头中返回新的 token
                return $this->fail('已刷新token',$token,401);
//                return $this->setAuthenticationHeader($next($request), $token);
                // 使用一次性登录以保证此次请求的成功
//                Auth::guard('api')->onceUsingId($this->auth->manager()->getPayloadFactory()->buildClaimsCollection()->toPlainArray()['sub']);
            } catch (JWTException $exception) {
//                // 如果捕获到此异常，即代表 refresh 也过期了，用户无法刷新令牌，需要重新登录。
//                throw new UnauthorizedHttpException('jwt-auth', $exception->getMessage());
                //refresh_token过期 Token has expired and can no longer be refreshed
                //token过期 在此拿旧的token访问 报错The token has been blacklisted
                if($exception->getMessage()=="The token has been blacklisted."){
                    throw new MyException('旧token进入黑名单，无法使用');
                }else if($exception->getMessage()=="Unauthenticated"){
                    throw new MyException('Unauthenticated');
                }else{
                    return $this->fail('refresh_token已过期，请重新登录','',402);
                }
           }
        }
    }

}

