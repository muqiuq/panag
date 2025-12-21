const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

module.exports = async () => {
  const root = path.join(__dirname, '..');
  const dbPath = path.join(root, 'data', 'panag.sqlite');
  const mockPath = path.join(root, 'data', 'mock_address_list.json');
  const setupFlag = path.join(root, 'setup-completed.txt');

  fs.rmSync(dbPath, { force: true });
  fs.rmSync(mockPath, { force: true });
  execSync('php test/create_demo_data.php', { stdio: 'inherit', cwd: root });
  fs.writeFileSync(setupFlag, 'created by tests');
};
