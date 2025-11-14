/*
 * Complete this script so that it is able to add a superuser to the database
 * Usage example: 
 *   node prisma/createsu.js clive123 clive.su@mail.utoronto.ca SuperUser123!
 */
'use strict';

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const bcrypt = require('bcrypt');

async function main() {
  const args = process.argv.slice(2);

  if (args.length !== 3) {
    console.error('Usage: node prisma/createsu.js <utorid> <email> <password>');
    process.exit(1);
  }

  const [utorid, email, password] = args;

  if (utorid.length < 7 || utorid.length > 8) {
    console.error('Error: utorid must be 7–8 characters.');
    process.exit(1);
  }

  if (!email.endsWith('@mail.utoronto.ca') && !email.endsWith('@utoronto.ca')) {
    console.error('Error: email must be a valid UofT address.');
    process.exit(1);
  }

  const hashed = await bcrypt.hash(password, 10);

  try {
    const exists = await prisma.user.findFirst({
      where: { OR: [{ utorid }, { email }] }
    });

    if (exists) {
      console.error('Error: User with this utorid/email already exists.');
      process.exit(1);
    }

    const newUser = await prisma.user.create({
      data: {
        utorid,
        name: utorid,
        email,
        password: hashed,
        role: 'superuser',
        verified: true,
        activated: true,
        suspicious: false,
        points: 0
      }
    });

    console.log('✔ Superuser created successfully:');
    console.log(newUser);

  } catch (err) {
    console.error('Error creating superuser:', err);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();