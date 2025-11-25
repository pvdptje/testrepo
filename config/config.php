<?php 

return [
    'routes' => [
        // route action names where we should check for spam
        'App\Http\Controllers\FormController@store'
    ],

    // place to sent the spam bots to when we detect spam  
    'redirect_to' => [
        '/bedankt'
    ],

    // everything above this treshhold is marked as spam
    'threshold' => 0.7
];