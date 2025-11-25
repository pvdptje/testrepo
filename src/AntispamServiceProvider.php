<?php

namespace Gomotion\Antispam;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class AntispamServiceProvider extends ServiceProvider {

    public function boot(Router $router)
    {
        $this->publishes([
            __DIR__.'/../config/config.php' => config_path('antispam.php'),
        ]);

        $router->pushMiddlewareToGroup('web', InterceptSpam::class);
    }
}