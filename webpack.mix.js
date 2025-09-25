let mix = require('laravel-mix');
const path = require('path');
const AutoImport = require('unplugin-auto-import/webpack');
const Components = require('unplugin-vue-components/webpack');
const { ElementPlusResolver } = require('unplugin-vue-components/resolvers');

mix.webpackConfig({
    module: {
        rules: [{
            test: /\.mjs$/,
            resolve: {fullySpecified: false},
            include: /node_modules/,
            type: "javascript/auto"
        }]
    },
    plugins: [
        AutoImport({
            resolvers: [ElementPlusResolver()],
        }),
        Components({
            resolvers: [ElementPlusResolver()],
            directives: false
        }),
    ],
    resolve: {
        extensions: ['.js', '.vue', '.json'],
        alias: {
            '@': path.resolve(__dirname, 'src/admin')
        }
    }
});

mix
    .js('src/admin/app.js', 'dist/admin/app.js').vue({ version: 3 })
    .js('src/public/magic_url.js', 'dist/public/fls_login.js')
    .js('src/public/login_helper.js', 'dist/public/login_helper.js')
    .sass('src/public/login_customizer.scss', 'dist/public/login_customizer.css')
    .copy('src/images', 'dist/images')
    .copy('src/libs', 'dist/libs')
    .copy([
        'node_modules/ace-builds/src-min-noconflict/mode-css.js',
        'node_modules/ace-builds/src-min-noconflict/theme-monokai.js'
    ], 'dist/admin/');
