let runActive = false;

const setRunActive = (value) => {
    runActive = Boolean(value);
};

const isRunActive = () => runActive;

module.exports = { setRunActive, isRunActive };
