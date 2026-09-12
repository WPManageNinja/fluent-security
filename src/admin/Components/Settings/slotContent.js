import {Comment, Fragment, Text} from 'vue';

/**
 * Whether a slot actually puts anything on the page.
 *
 * `v-if="$slots.thing"` does not answer this. A slot passed with a `v-if` that is
 * currently false still exists - it renders a comment - so asking whether it was passed
 * leaves an empty bordered box on the screen wherever the answer decides a wrapper. Ask
 * what it rendered instead.
 *
 * A function rather than a computed, because a slot has to be called during render.
 */
export const rendersSomething = (slot) => slot ? nodesRenderSomething(slot()) : false;

const nodesRenderSomething = (nodes) => (nodes || []).some(node => {
    if (node.type === Comment) {
        return false;
    }

    if (node.type === Text) {
        return String(node.children || '').trim() !== '';
    }

    /* A `<template v-if>` holding several rows arrives as one fragment. */
    if (node.type === Fragment) {
        return nodesRenderSomething(node.children);
    }

    return true;
});
