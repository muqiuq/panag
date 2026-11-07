<?php
// Small helpers for the views.

/** Escape a value for HTML text and attribute content. */
function e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function role_badge_class(string $role): string
{
    return ['admin' => 'bg-danger', 'superuser' => 'bg-primary'][$role] ?? 'bg-secondary';
}

/**
 * Header cell of a server-side sorted table (audit log). Renders like the client-side sortable headers
 * of public/js/table-sort.js: a link inside the <th>, aria-sort on the active column.
 */
function sort_header_cell(string $label, string $key, string $currentKey, string $currentDir, array $query): string
{
    $active = $key === $currentKey;
    $nextDir = $active && $currentDir === 'asc' ? 'desc' : 'asc';
    $href = '?' . http_build_query(array_merge($query, ['sort' => $key, 'dir' => $nextDir, 'page' => 1]));
    $ariaSort = $active ? ' aria-sort="' . ($currentDir === 'asc' ? 'ascending' : 'descending') . '"' : '';
    return '<th' . $ariaSort . '><a class="sort-btn" href="' . e($href) . '">' . e($label) . '</a></th>';
}
