<?php
// Pagination bar for server-side paginated tables (audit log, alerts).
// Expects $pagination = ['page' => int, 'pages' => int, 'link' => fn(int $page): string, 'label' => string].
/** @var array{page: int, pages: int, link: callable, label: string} $pagination */
$__p = $pagination;
if ($__p['pages'] <= 1) {
    return;
}
$__current = $__p['page'];
$__last = $__p['pages'];
$__numbers = array_values(array_unique(array_filter(
    [1, $__current - 2, $__current - 1, $__current, $__current + 1, $__current + 2, $__last],
    fn($n) => $n >= 1 && $n <= $__last
)));
sort($__numbers);
$__item = static function (int $target, string $text, string $aria, bool $disabled = false, bool $active = false) use ($__p): string {
    if ($disabled || $active) {
        return '<li class="page-item' . ($active ? ' active' : ' disabled') . '"' . ($active ? ' aria-current="page"' : '') . '><span class="page-link"' . ($aria !== '' ? ' aria-label="' . e($aria) . '"' : '') . '>' . $text . '</span></li>';
    }
    return '<li class="page-item"><a class="page-link" href="' . e(($__p['link'])($target)) . '"' . ($aria !== '' ? ' aria-label="' . e($aria) . '"' : '') . '>' . $text . '</a></li>';
};
?>
<nav aria-label="<?= e($__p['label']) ?>" class="my-3">
  <ul class="pagination pagination-sm flex-wrap mb-0">
    <?= $__item(1, '&laquo;', 'First page', $__current <= 1) ?>
    <?= $__item(max(1, $__current - 1), '&lsaquo;', 'Previous page', $__current <= 1) ?>
    <?php $__prev = 0; foreach ($__numbers as $__n): ?>
      <?php if ($__prev && $__n > $__prev + 1): ?>
        <li class="page-item disabled"><span class="page-link">…</span></li>
      <?php endif; ?>
      <?= $__item($__n, (string)$__n, 'Page ' . $__n, false, $__n === $__current) ?>
    <?php $__prev = $__n; endforeach; ?>
    <?= $__item(min($__last, $__current + 1), '&rsaquo;', 'Next page', $__current >= $__last) ?>
    <?= $__item($__last, '&raquo;', 'Last page', $__current >= $__last) ?>
  </ul>
</nav>
