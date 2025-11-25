<?php

namespace Gomotion\Antispam;

use App\Support\SpamHelper;
use Closure;
use Illuminate\Support\Arr;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class InterceptSpam
{
    public function handle(Request $request, Closure $next)
    {
        $route = $request->route();
        $action = $route ? $route->getActionName() : null;
        $config = config('antispam');
        $routesToRunOn = $config['routes'] ?? [];
        $threshold = $config['threshold'] ?? 0.7;
        $data = $request->all();

        if(!in_array($action, $routesToRunOn)){
            return $next($request);
        }

        if (!$request->has('smart')) {
            return $next($request);
        }

        if ($this->payloadIsStructured($data)) {
            $isSpam = $this->analyzeStructuredPayload($data, $threshold);
        } else {
            // oudere producties hebben geen 'type'
            $isSpam = $this->analyzeFlatPayload($data, $threshold);
        }
   
        if ($isSpam) {
            return $this->handleSpamResponse($request, $config);
        }

        return $next($request);
    }

    private function payloadIsStructured(array $data): bool
    {
        $first = reset($data);        
        return is_array($first) && array_key_exists('type', $first) && array_key_exists('value', $first);
    }

    /**
     * Fallback: Flattens the request and checks ALL strings.
     */
    private function analyzeFlatPayload(array $data, float $threshold): bool
    {
        $scores = collect(Arr::dot($data))
            ->filter(function ($value) {
                return is_string($value)
                    && $value !== ''
                    && !filter_var($value, FILTER_VALIDATE_EMAIL);
            })
            ->map(function ($value) {
                return SpamHelper::spamRandomStringScore($value);
            });

        if ($scores->isEmpty()) {
            return false;
        }

        return $scores->median() >= $threshold;
    }

    /**
     * Preferred: Checks only specific input types (text/textarea).
     */
    private function analyzeStructuredPayload(array $data, float $threshold): bool
    {
        $scores = collect($data)
            ->filter(function ($row) {
                return is_array($row) 
                    && isset($row['type'], $row['value'])
                    && in_array($row['type'], ['text', 'textarea'], true)
                    && is_string($row['value'])
                    && $row['value'] !== ''
                    && filter_var($row['value'], FILTER_VALIDATE_EMAIL) === false;
            })
            ->pluck('value')
            ->map(fn(string $value) => SpamHelper::spamRandomStringScore($value));

        if ($scores->isEmpty()) {
            return false;
        }

        return $scores->median() >= $threshold;
    }

    /**
     * Handles the response when spam is detected.
     */
    private function handleSpamResponse(Request $request, array $config)
    {
        if ($request->wantsJson() || $request->ajax()) {
            $message = 'Message sent successfully';
            return new JsonResponse($message);
        }

        $redirectUrl = $config['redirect_to'] ?? '/';
        return redirect($redirectUrl);
    }
}
