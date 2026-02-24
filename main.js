// public/js/main.js
// Общие функции для всего сайта

// Обновление счетчика товаров в корзине
async function updateCartCount() {
    try {
        const response = await fetch('/api/cart');
        if (response.ok) {
            const cart = await response.json();
            const cartCountElements = document.querySelectorAll('#cart-count');
            cartCountElements.forEach(el => {
                el.textContent = cart.count;
            });
        }
    } catch (error) {
        console.error('Ошибка обновления счетчика корзины:', error);
    }
}

// Форматирование цены
function formatPrice(price) {
    return new Intl.NumberFormat('ru-RU', {
        style: 'currency',
        currency: 'RUB',
        minimumFractionDigits: 0
    }).format(price);
}

// Получение параметров из URL
function getUrlParams() {
    const params = new URLSearchParams(window.location.search);
    return params;
}

// Показ уведомления
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;
    notification.textContent = message;
    notification.style.position = 'fixed';
    notification.style.top = '20px';
    notification.style.right = '20px';
    notification.style.zIndex = '9999';
    notification.style.minWidth = '300px';

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Валидация email
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Валидация телефона
function validatePhone(phone) {
    const re = /^[\d\s\+\-\(\)]{10,20}$/;
    return re.test(phone);
}

// Дебаунс для поиска
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    updateCartCount();
});

// Экспорт функций для использования в других скриптах
window.shopUtils = {
    updateCartCount,
    formatPrice,
    getUrlParams,
    showNotification,
    validateEmail,
    validatePhone,
    debounce
};