<?php
function normalize_url(string $url): string {
    $url = trim($url);
    $url = trim($url, "\"' \t\n\r\0\x0B");
    if (!preg_match('#^[a-z]+://#i', $url)) {
        $url = 'http://' . $url;
    }
    $parts = parse_url($url);
    if ($parts === false || empty($parts['host'])) return rtrim($url, '/');

    $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : 'http';
    $host = strtolower($parts['host']);
    $path = isset($parts['path']) ? rtrim($parts['path'], '/') : '';
    $query = isset($parts['query']) ? '?' . $parts['query'] : '';
    $port = (isset($parts['port']) && !in_array($parts['port'], [80,443])) ? ':' . $parts['port'] : '';
    $normalized = $scheme . '://' . $host . $port . ($path === '' ? '' : '/' . ltrim($path, '/')) . $query;
    return rtrim($normalized, '/');
}
