// server.js
// Главный серверный файл интернет-магазина
// Объединяет весь бэкенд в один файл
const path = require('path');
const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs'); 
const cookieParser = require('cookie-parser');
const app = express();
const PORT = process.env.PORT || 3000;
// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(cookieParser());
// Настройка сессий
app.use(session({
    secret: 'shop_secret_key_2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,          // В продакшне должно быть true с HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 часа
    }
}));

// Инициализация приложения

// Middleware для проверки авторизации и прав доступа
const requireAuth = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }
    next();
};
// Middleware для проверки прав администратора (только для matveev.tu@gmail.com)
const requireAdmin = async (req, res, next) => {
    try {
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ error: 'Требуется авторизация' });
        }

        // Получаем email пользователя из базы данных
        const result = await pool.query(
            'SELECT email FROM users WHERE id = $1',
            [req.session.userId]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Пользователь не найден' });
        }

        const userEmail = result.rows[0].email;

        // Проверяем, что это администратор (ваш email)
        if (userEmail !== 'matveev.tu@gmail.com') {
            return res.status(403).json({ error: 'Доступ запрещен. Только для администратора' });
        }

        // Добавляем информацию о пользователе в req для дальнейшего использования
        req.userEmail = userEmail;
        next();
    } catch (error) {
        console.error('Ошибка проверки прав доступа:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
};
// Middleware для проверки доступа к страницам статистики
app.use(['/statistics.html', '/analytics.html'], async (req, res, next) => {
    // Если пользователь не авторизован, перенаправляем на страницу входа
    if (!req.session || !req.session.userId) {
        return res.redirect('/account.html');
    }

    try {
        // Проверяем email пользователя
        const result = await pool.query(
            'SELECT email FROM users WHERE id = $1',
            [req.session.userId]
        );

        if (result.rows.length === 0) {
            return res.redirect('/account.html');
        }

        const userEmail = result.rows[0].email;

        // Если это не администратор - показываем страницу 403
        if (userEmail !== 'matveev.tu@gmail.com') {
            return res.sendFile(path.join(__dirname, 'public', '403.html'));
        }

        // Если администратор - пропускаем дальше
        next();
    } catch (error) {
        console.error('Ошибка проверки доступа:', error);
        res.redirect('/');
    }
});
// Middleware для логирования всех запросов
// Middleware для логирования всех запросов (кроме API статистики)
app.use((req, res, next) => {
    const start = Date.now();

    // НЕ логируем запросы к API статистики и аналитики
    if (req.url.includes('/api/analytics/') || req.url.includes('/api/statistics/')) {
        return next();
    }

    let visitId = req.cookies?.visit_id;
    if (!visitId) {
        visitId = 'VISIT-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        res.cookie('visit_id', visitId, { maxAge: 365 * 24 * 60 * 60 * 1000, httpOnly: true });
    }

    const userId = req.session?.userId || 'guest';

    res.on('finish', () => {
        const duration = Date.now() - start;

        // Логируем только GET запросы к страницам (не API)
        if (req.method === 'GET' && !req.url.startsWith('/api/')) {
            const logEntry = {
                timestamp: new Date().toISOString(),
                visit_id: visitId,
                user_id: userId,
                method: req.method,
                url: req.url,
                ip: req.ip || req.connection.remoteAddress,
                user_agent: req.get('User-Agent') || 'unknown',
                referer: req.get('Referer') || 'direct',
                status: res.statusCode,
                duration: duration
            };

            const logLine = JSON.stringify(logEntry) + '\n';
            const date = new Date().toISOString().split('T')[0];
            const logFile = path.join(logsDir, `access-${date}.log`);

            fs.appendFile(logFile, logLine, (err) => {
                if (err) console.error('Ошибка записи лога:', err);
            });
        }

        // Логируем успешные заказы
        if (req.url.includes('/api/orders/create') && req.method === 'POST' && res.statusCode === 200) {
            const salesLogEntry = {
                timestamp: new Date().toISOString(),
                visit_id: visitId,
                user_id: userId,
                event: 'order_created',
                url: req.url
            };

            const salesLogLine = JSON.stringify(salesLogEntry) + '\n';
            const date = new Date().toISOString().split('T')[0];
            const salesLogFile = path.join(logsDir, `sales-${date}.log`);

            fs.appendFile(salesLogFile, salesLogLine, (err) => {
                if (err) console.error('Ошибка записи лога продаж:', err);
            });
        }
    });

    next();
});
// Эндпоинт для получения статистики по продажам из логов
app.get('/api/analytics/sales', requireAdmin, async (req, res) => {
    try {
        const { period = 'month' } = req.query;

        const files = fs.readdirSync(logsDir);
        const salesFiles = files.filter(f => f.startsWith('sales-') && f.endsWith('.log'));

        const days = period === 'week' ? 7 : period === 'month' ? 30 : period === 'year' ? 365 : 30;
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);

        let sales = {
            total_checkouts: 0,
            successful_orders: 0,
            by_hour: Array(24).fill(0),
            by_day: {}
        };

        salesFiles.forEach(file => {
            const fileDate = file.replace('sales-', '').replace('.log', '');
            if (new Date(fileDate) < cutoffDate) return;

            const content = fs.readFileSync(path.join(logsDir, file), 'utf-8');
            const lines = content.split('\n').filter(line => line.trim());

            lines.forEach(line => {
                try {
                    const entry = JSON.parse(line);
                    sales.total_checkouts++;

                    if (entry.status === 200) {
                        sales.successful_orders++;
                    }

                    const hour = new Date(entry.timestamp).getHours();
                    sales.by_hour[hour]++;

                    const day = entry.timestamp.split('T')[0];
                    sales.by_day[day] = (sales.by_day[day] || 0) + 1;

                } catch (e) { }
            });
        });

        res.json(sales);
    } catch (error) {
        console.error('Ошибка получения аналитики продаж:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ==================== ЛОГИРОВАНИЕ ПОСЕЩАЕМОСТИ ====================




// Создание папки для логов, если её нет
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
}



// Middleware для работы с cookies (если ещё не установлен)


// ==================== СЧЕТЧИКИ ПОСЕЩЕНИЙ ====================

// Эндпоинт для получения статистики посещений
app.get('/api/analytics/visits', requireAdmin, async (req, res) => {
    try {
        const { period = 'day' } = req.query;

        // Читаем все лог-файлы
        const files = fs.readdirSync(logsDir);
        const logFiles = files.filter(f => f.startsWith('access-') && f.endsWith('.log'));

        let stats = {
            total_visits: 0,
            unique_visitors: new Set(),
            page_views: {},
            referrers: {},
            browsers: {},
            hourly: Array(24).fill(0),
            daily: {}
        };

        // Определяем, сколько дней назад смотреть
        const days = period === 'week' ? 7 : period === 'month' ? 30 : period === 'year' ? 365 : 1;
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);

        // Парсим логи
        logFiles.forEach(file => {
            const fileDate = file.replace('access-', '').replace('.log', '');
            if (new Date(fileDate) < cutoffDate) return;

            const content = fs.readFileSync(path.join(logsDir, file), 'utf-8');
            const lines = content.split('\n').filter(line => line.trim());

            lines.forEach(line => {
                try {
                    const entry = JSON.parse(line);

                    stats.total_visits++;
                    stats.unique_visitors.add(entry.visit_id);

                    // Статистика по страницам
                    const page = entry.url.split('?')[0];
                    stats.page_views[page] = (stats.page_views[page] || 0) + 1;

                    // Статистика по источникам
                    if (entry.referer && entry.referer !== 'direct') {
                        try {
                            const refererUrl = new URL(entry.referer);
                            const domain = refererUrl.hostname;
                            stats.referrers[domain] = (stats.referrers[domain] || 0) + 1;
                        } catch {
                            stats.referrers[entry.referer] = (stats.referrers[entry.referer] || 0) + 1;
                        }
                    } else {
                        stats.referrers.direct = (stats.referrers.direct || 0) + 1;
                    }

                    // Статистика по браузерам
                    const ua = entry.user_agent;
                    if (ua.includes('Chrome')) stats.browsers.Chrome = (stats.browsers.Chrome || 0) + 1;
                    else if (ua.includes('Firefox')) stats.browsers.Firefox = (stats.browsers.Firefox || 0) + 1;
                    else if (ua.includes('Safari')) stats.browsers.Safari = (stats.browsers.Safari || 0) + 1;
                    else if (ua.includes('Edge')) stats.browsers.Edge = (stats.browsers.Edge || 0) + 1;
                    else stats.browsers.Other = (stats.browsers.Other || 0) + 1;

                    // Почасовая статистика
                    const hour = new Date(entry.timestamp).getHours();
                    stats.hourly[hour] = (stats.hourly[hour] || 0) + 1;

                    // Ежедневная статистика
                    const day = entry.timestamp.split('T')[0];
                    stats.daily[day] = (stats.daily[day] || 0) + 1;

                } catch (e) {
                    // Пропускаем битые строки
                }
            });
        });

        stats.unique_visitors = stats.unique_visitors.size;

        res.json(stats);
    } catch (error) {
        console.error('Ошибка получения аналитики:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});



// Настройка подключения к PostgreSQL
const pool = new Pool({
    user: 'postgres',           // Замените на вашего пользователя
    host: 'localhost',
    database: 'shop_db',        // Название базы данных
    password: '',       // Замените на ваш пароль
    port: 5432,
});





// ==================== API МАРШРУТЫ ====================

// ----- АВТОРИЗАЦИЯ -----

// Регистрация пользователя
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, firstName, lastName, phone } = req.body;
        
        // Проверка на существующего пользователя
        const userExists = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        );
        
        if (userExists.rows.length > 0) {
            return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
        }
        
        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Создание пользователя
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, first_name, last_name, phone) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, first_name, last_name',
            [email, hashedPassword, firstName, lastName, phone]
        );
        
        const user = result.rows[0];
        req.session.userId = user.id;
        req.session.userEmail = user.email;
        
        res.json({ 
            success: true, 
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name
            }
        });
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Вход пользователя
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const result = await pool.query(
            'SELECT id, email, password_hash, first_name, last_name FROM users WHERE email = $1',
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        
        req.session.userId = user.id;
        req.session.userEmail = user.email;
        
        res.json({ 
            success: true, 
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name
            }
        });
    } catch (error) {
        console.error('Ошибка входа:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Выход пользователя
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Проверка авторизации
app.get('/api/check-auth', (req, res) => {
    if (req.session.userId) {
        res.json({ authenticated: true, userId: req.session.userId });
    } else {
        res.json({ authenticated: false });
    }
});

// ----- ТОВАРЫ -----

// Получение всех товаров с фильтрацией
app.get('/api/products', async (req, res) => {
    try {
        const { 
            category, 
            minPrice, 
            maxPrice, 
            brand,
            inStock,
            sort,
            search 
        } = req.query;
        
        let query = 'SELECT * FROM products WHERE 1=1';
        const params = [];
        let paramCount = 1;
        
        // Поиск по названию
        if (search) {
            params.push(`%${search}%`);
            query += ` AND (name ILIKE $${paramCount} OR description ILIKE $${paramCount})`;
            paramCount++;
        }
        
        // Фильтр по категории
        if (category && category !== 'all') {
            params.push(category);
            query += ` AND category = $${paramCount}`;
            paramCount++;
        }
        
        // Фильтр по бренду
        if (brand && brand !== 'all') {
            params.push(brand);
            query += ` AND brand = $${paramCount}`;
            paramCount++;
        }
        
        // Фильтр по минимальной цене
        if (minPrice) {
            params.push(parseFloat(minPrice));
            query += ` AND price >= $${paramCount}`;
            paramCount++;
        }
        
        // Фильтр по максимальной цене
        if (maxPrice) {
            params.push(parseFloat(maxPrice));
            query += ` AND price <= $${paramCount}`;
            paramCount++;
        }
        
        // Фильтр по наличию
        if (inStock === 'true') {
            query += ' AND in_stock > 0';
        }
        
        // Сортировка
        switch (sort) {
            case 'price_asc':
                query += ' ORDER BY price ASC';
                break;
            case 'price_desc':
                query += ' ORDER BY price DESC';
                break;
            case 'name_asc':
                query += ' ORDER BY name ASC';
                break;
            case 'name_desc':
                query += ' ORDER BY name DESC';
                break;
            case 'newest':
                query += ' ORDER BY created_at DESC';
                break;
            default:
                query += ' ORDER BY name ASC';
        }
        
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка получения товаров:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Получение одного товара по ID
app.get('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Ошибка получения товара:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Получение уникальных категорий
app.get('/api/categories', async (req, res) => {
    try {
        const result = await pool.query('SELECT DISTINCT category FROM products ORDER BY category');
        res.json(result.rows.map(row => row.category));
    } catch (error) {
        console.error('Ошибка получения категорий:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Получение уникальных брендов
app.get('/api/brands', async (req, res) => {
    try {
        const result = await pool.query('SELECT DISTINCT brand FROM products WHERE brand IS NOT NULL ORDER BY brand');
        res.json(result.rows.map(row => row.brand));
    } catch (error) {
        console.error('Ошибка получения брендов:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ----- КОРЗИНА -----

// Получение корзины пользователя
app.get('/api/cart', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        const result = await pool.query(`
            SELECT 
                ci.id,
                ci.quantity,
                p.id as product_id,
                p.name,
                p.price,
                p.image_url,
                p.in_stock,
                (p.price * ci.quantity) as total
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.user_id = $1
            ORDER BY ci.added_at DESC
        `, [userId]);
        
        // Подсчет общей суммы
        const total = result.rows.reduce((sum, item) => sum + parseFloat(item.total), 0);
        
        res.json({
            items: result.rows,
            total: total,
            count: result.rows.length
        });
    } catch (error) {
        console.error('Ошибка получения корзины:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Добавление товара в корзину
app.post('/api/cart/add', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { productId, quantity = 1 } = req.body;
        
        // Проверка наличия товара
        const productCheck = await pool.query(
            'SELECT in_stock FROM products WHERE id = $1',
            [productId]
        );
        
        if (productCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }
        
        if (productCheck.rows[0].in_stock < quantity) {
            return res.status(400).json({ error: 'Недостаточно товара на складе' });
        }
        
        // Проверка, есть ли уже товар в корзине
        const existingItem = await pool.query(
            'SELECT id, quantity FROM cart_items WHERE user_id = $1 AND product_id = $2',
            [userId, productId]
        );
        
        if (existingItem.rows.length > 0) {
            // Обновляем количество
            const newQuantity = existingItem.rows[0].quantity + quantity;
            await pool.query(
                'UPDATE cart_items SET quantity = $1 WHERE id = $2',
                [newQuantity, existingItem.rows[0].id]
            );
        } else {
            // Добавляем новый товар
            await pool.query(
                'INSERT INTO cart_items (user_id, product_id, quantity) VALUES ($1, $2, $3)',
                [userId, productId, quantity]
            );
        }
        
        res.json({ success: true, message: 'Товар добавлен в корзину' });
    } catch (error) {
        console.error('Ошибка добавления в корзину:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Обновление количества товара в корзине
app.put('/api/cart/update/:itemId', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { itemId } = req.params;
        const { quantity } = req.body;
        
        if (quantity < 1) {
            return res.status(400).json({ error: 'Количество должно быть больше 0' });
        }
        
        // Проверка, что товар принадлежит пользователю
        const itemCheck = await pool.query(
            'SELECT * FROM cart_items WHERE id = $1 AND user_id = $2',
            [itemId, userId]
        );
        
        if (itemCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Товар не найден в корзине' });
        }
        
        await pool.query(
            'UPDATE cart_items SET quantity = $1 WHERE id = $2',
            [quantity, itemId]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Ошибка обновления корзины:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Удаление товара из корзины
app.delete('/api/cart/remove/:itemId', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { itemId } = req.params;
        
        await pool.query(
            'DELETE FROM cart_items WHERE id = $1 AND user_id = $2',
            [itemId, userId]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Ошибка удаления из корзины:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Очистка корзины
app.delete('/api/cart/clear', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        await pool.query(
            'DELETE FROM cart_items WHERE user_id = $1',
            [userId]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Ошибка очистки корзины:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ----- ЗАКАЗЫ -----

// Создание заказа
app.post('/api/orders/create', requireAuth, async (req, res) => {
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        
        const userId = req.session.userId;
        const { shippingAddress, paymentMethod, comment } = req.body;
        
        // Получаем товары из корзины
        const cartItems = await client.query(`
            SELECT 
                ci.product_id,
                ci.quantity,
                p.name,
                p.price,
                p.in_stock
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.user_id = $1
        `, [userId]);
        
        if (cartItems.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Корзина пуста' });
        }
        
        // Проверка наличия товаров и расчет суммы
        let totalAmount = 0;
        for (const item of cartItems.rows) {
            if (item.in_stock < item.quantity) {
                await client.query('ROLLBACK');
                return res.status(400).json({ 
                    error: `Недостаточно товара "${item.name}" на складе. Доступно: ${item.in_stock}` 
                });
            }
            totalAmount += parseFloat(item.price) * item.quantity;
        }
        
        // Генерация номера заказа
        const orderNumber = 'ORD-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
        
        // Создание заказа
        const orderResult = await client.query(
            `INSERT INTO orders 
            (user_id, order_number, total_amount, shipping_address, payment_method, comment, status) 
            VALUES ($1, $2, $3, $4, $5, $6, 'Новый') 
            RETURNING id, order_number`,
            [userId, orderNumber, totalAmount, shippingAddress, paymentMethod, comment]
        );
        
        const orderId = orderResult.rows[0].id;
        
        // Добавление товаров в заказ
        for (const item of cartItems.rows) {
            const itemTotal = parseFloat(item.price) * item.quantity;
            await client.query(
                `INSERT INTO order_items 
                (order_id, product_id, product_name, quantity, price, total) 
                VALUES ($1, $2, $3, $4, $5, $6)`,
                [orderId, item.product_id, item.name, item.quantity, item.price, itemTotal]
            );
            
            // Обновление остатков на складе
            await client.query(
                'UPDATE products SET in_stock = in_stock - $1 WHERE id = $2',
                [item.quantity, item.product_id]
            );
        }
        
        // Очистка корзины
        await client.query('DELETE FROM cart_items WHERE user_id = $1', [userId]);
        
        await client.query('COMMIT');
        
        res.json({ 
            success: true, 
            orderId: orderId,
            orderNumber: orderResult.rows[0].order_number
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Ошибка создания заказа:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    } finally {
        client.release();
    }
});

// Получение заказов пользователя
app.get('/api/orders', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        const orders = await pool.query(`
            SELECT 
                o.*,
                json_agg(
                    json_build_object(
                        'id', oi.id,
                        'product_name', oi.product_name,
                        'quantity', oi.quantity,
                        'price', oi.price,
                        'total', oi.total
                    )
                ) as items
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            WHERE o.user_id = $1
            GROUP BY o.id
            ORDER BY o.order_date DESC
        `, [userId]);
        
        res.json(orders.rows);
    } catch (error) {
        console.error('Ошибка получения заказов:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Получение одного заказа
app.get('/api/orders/:orderId', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { orderId } = req.params;
        
        const order = await pool.query(`
            SELECT 
                o.*,
                json_agg(
                    json_build_object(
                        'id', oi.id,
                        'product_id', oi.product_id,
                        'product_name', oi.product_name,
                        'quantity', oi.quantity,
                        'price', oi.price,
                        'total', oi.total
                    )
                ) as items
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            WHERE o.id = $1 AND o.user_id = $2
            GROUP BY o.id
        `, [orderId, userId]);
        
        if (order.rows.length === 0) {
            return res.status(404).json({ error: 'Заказ не найден' });
        }
        
        res.json(order.rows[0]);
    } catch (error) {
        console.error('Ошибка получения заказа:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ----- ПОЛЬЗОВАТЕЛЬ -----

// Получение профиля пользователя
app.get('/api/user/profile', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        const result = await pool.query(
            'SELECT id, email, first_name, last_name, phone, address, created_at FROM users WHERE id = $1',
            [userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Ошибка получения профиля:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
// ==================== СТАТИСТИКА ПРОДАЖ ====================

// Получение общей статистики продаж
app.get('/api/statistics/overview', requireAdmin, async (req, res) => {
    try {
        // Проверка прав (только администратор)
        // Для учебного проекта пропускаем всех авторизованных

        // Общая статистика
        const totalStats = await pool.query(`
            SELECT 
                COUNT(DISTINCT o.id) as total_orders,
                COUNT(DISTINCT o.user_id) as total_customers,
                COALESCE(SUM(o.total_amount), 0) as total_revenue,
                COALESCE(AVG(o.total_amount), 0) as avg_order_value,
                COUNT(oi.id) as total_items_sold,
                MIN(o.order_date) as first_order_date,
                MAX(o.order_date) as last_order_date
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            WHERE o.status != 'Отменён'
        `);

        // Статистика по статусам заказов
        const statusStats = await pool.query(`
            SELECT 
                status,
                COUNT(*) as count,
                COALESCE(SUM(total_amount), 0) as total
            FROM orders
            GROUP BY status
            ORDER BY count DESC
        `);

        // Статистика по дням (последние 30 дней)
        const dailyStats = await pool.query(`
            SELECT 
                DATE(order_date) as date,
                COUNT(*) as orders_count,
                COALESCE(SUM(total_amount), 0) as revenue
            FROM orders
            WHERE order_date >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY DATE(order_date)
            ORDER BY date DESC
        `);

        res.json({
            overview: totalStats.rows[0],
            byStatus: statusStats.rows,
            daily: dailyStats.rows
        });
    } catch (error) {
        console.error('Ошибка получения статистики:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Статистика по товарам (самые продаваемые)
app.get('/api/statistics/top-products', requireAdmin, async (req, res) => {
    try {
        const { period = 'all', limit = 10 } = req.query;

        let dateFilter = '';
        if (period === 'week') {
            dateFilter = 'AND o.order_date >= CURRENT_DATE - INTERVAL \'7 days\'';
        } else if (period === 'month') {
            dateFilter = 'AND o.order_date >= CURRENT_DATE - INTERVAL \'30 days\'';
        } else if (period === 'year') {
            dateFilter = 'AND o.order_date >= CURRENT_DATE - INTERVAL \'1 year\'';
        }

        const result = await pool.query(`
            SELECT 
                p.id,
                p.name,
                p.category,
                p.price,
                COALESCE(SUM(oi.quantity), 0) as total_sold,
                COALESCE(SUM(oi.total), 0) as total_revenue,
                COUNT(DISTINCT o.id) as orders_count
            FROM products p
            LEFT JOIN order_items oi ON p.id = oi.product_id
            LEFT JOIN orders o ON oi.order_id = o.id ${dateFilter}
            WHERE o.status != 'Отменён' OR o.status IS NULL
            GROUP BY p.id, p.name, p.category, p.price
            ORDER BY total_sold DESC
            LIMIT $1
        `, [limit]);

        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка получения статистики по товарам:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Статистика по категориям
app.get('/api/statistics/by-category', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                p.category,
                COUNT(DISTINCT p.id) as products_count,
                COALESCE(SUM(oi.quantity), 0) as items_sold,
                COALESCE(SUM(oi.total), 0) as revenue,
                COALESCE(AVG(oi.price), 0) as avg_price
            FROM products p
            LEFT JOIN order_items oi ON p.id = oi.product_id
            LEFT JOIN orders o ON oi.order_id = o.id
            WHERE o.status != 'Отменён' OR o.status IS NULL
            GROUP BY p.category
            ORDER BY revenue DESC
        `);

        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка получения статистики по категориям:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Статистика по пользователям (лучшие покупатели)
app.get('/api/statistics/top-customers', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                u.id,
                u.email,
                u.first_name,
                u.last_name,
                COUNT(DISTINCT o.id) as orders_count,
                COALESCE(SUM(o.total_amount), 0) as total_spent,
                MAX(o.order_date) as last_order_date
            FROM users u
            LEFT JOIN orders o ON u.id = o.user_id
            WHERE o.status != 'Отменён' OR o.status IS NULL
            GROUP BY u.id, u.email, u.first_name, u.last_name
            HAVING COUNT(DISTINCT o.id) > 0
            ORDER BY total_spent DESC
            LIMIT 20
        `);

        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка получения статистики по пользователям:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
// Обновление профиля пользователя
app.put('/api/user/profile', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { firstName, lastName, phone, address } = req.body;
        
        await pool.query(
            'UPDATE users SET first_name = $1, last_name = $2, phone = $3, address = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5',
            [firstName, lastName, phone, address, userId]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Ошибка обновления профиля:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
    console.log(`Для просмотра магазина откройте браузер и перейдите по адресу:`);
    console.log(`http://localhost:${PORT}`);
});