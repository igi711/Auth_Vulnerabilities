# Laravel Authentication Vulnerabilities: Example and Prevention
***
## Contents of this file
***
- Introduction
- URL to the example
- Vulnerabilities
- Example and Prevention
- Maintainers

## Introduction
***
The Laravel Framework provides in-built security features and is meant to be secure by default.
Laravel security practices are a very extensive topic. This research discusses basic security issues.

## URL to the example
***
I creted trhee authentication types to my research. These user authentications are not completly secure.
I made it to show the code implement authenticators.
Check these out:

- Simple Authentication - (https://github.com/igi711/User_Authentication.git)
- Authentication with 2FA - (https://github.com/igi711/UserAuth2FA.git)
- Authentication with Google - (https://github.com/igi711/Google_User_Auth.git)

## Vulnerabilities
***
- Cross Site Scripting (XSS)
- Cross Site Request Forgery (CSRF)
- SQL Injection
- Broken Authentication
- Week login credentials
- Useful links

## Example and Prevention
***

## Cross Site Scripting (XSS)
***
### Input sanitization
```
$php artisan make:middleware
XssSanitization
```
### app/Http/Middleware/XssSanitization.php
```
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class XssSanitizier
{
public function handle(Request $request,
Closure $next)
{
$input = $request->all();

array_walk_recursive($input,
function(&$input) {
$input = strip_tags($input);
});

$request->merge($input);

return $next)$request);
}
}
```
### Next, register this in middleware : app/Http/Kernel.php
```
class Kernel extends HttpKernel
{
....
protected $routeMiddleware = [
'auth' => \App\Http\Middleware\Authenticate::class,

....

'XssSanitizer' => \App\Http\Middleware\XssSanitizer::class,
];
}

Route::group(['middleware' => ['XssSanitizer']], function () {
Route::get('view-register', 'RegisterController@viewRegisterPage');
Route::post('register', 'RegisterController@registerAction);
});
```

### Vulnerability can result in the following:
```
{!! $ticket->decription !!}
```

### Safe example:
```
{{ $ticket->decription }}
```
Using libraries that are specifically designed to sanitize HTML input:
- PHP Html Purifier
- .Net HTML sanitizer
- OWASP Java HTML Sanitizer

## Cross Site Request Forgery (CSRF)
***
### If you are manually creating forms in standard HTML using Blade templates (not a recommended choice), you must pass the CSRF token there as shown below:
```
<form name="eexample">

{{ csrf_field() }}

<!-- Other inputs -->

</form>
```
## SQL Injection
***
- To avoid SQL injections, user input should be authenticated for a definite set of rules for syntax, type, and length.
- Avoid raw queries
- Applications built with Laravel may display sensitive information such as database queries during unhandled exceptions in Error Messages.
- Confidentiality of valuable data stored in the database:

  ![password](https://github.com/igi711/Auth_Vulnerabilities/blob/main/passw.png)
  
- useful link : [StackHawk] - (https://www.stackhawk.com/blog/sql-injection-prevention-laravel/)


## Broken Authentication
***
Prevention:
- Never commit any default login details or sensitive API credentials to your code repository. Maintain these settings in the .env file in the project root.
- Use CAPTCHA for any endpoints that can be exploited using brute-force techniques. 
- Multi-factor authentication (Captcha tests, fingerprints, voice, biometrics, etc...)


## Weak login credentials
***
- Weak, short, too simple passwords (etc: 123456, password)
- The password must vontain capital letters, punctuation marks and numbers and be ling enough.


## Useful links:
***
- [OWASP Cheatsheets] - (https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html)
- [SNYK] - (https://snyk.io/blog/tips-for-securing-php-laravel/)
- [Cloudways] - (https://www.cloudways.com/blog/prevent-laravel-xss-exploits/)

## Maintainers
***
- Brigitta Bujdosone Kovacs -(ISC)² Candidate- [kovacsbrigi.hu](https://kovacsbrigi.hu/) 
