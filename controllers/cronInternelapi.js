const ShortenedUrl = require('../models/test');
const PaidUser = require("../models/paiduser");


exports.cronInternalApi = async (req, res) => {
  if (req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).send('Unauthorized');
  }
  console.log('Cron job triggered');

  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Normalize to only compare date

    // Step 1: Expire outdated short links
    const urlUpdateResult = await ShortenedUrl.updateMany(
      {
        expirationDate: { $lte: today },
        active: 'Y',
      },
      {
        $set: { active: 'D' },
      }
    );

    const updatedLinks = await ShortenedUrl.find({
      expirationDate: { $lte: today },
      active: 'D',
    });

    // Step 2: Expire user plans
    const userUpdateResult = await PaidUser.updateMany(
      {
        expiredDate: { $lte: today },
        planStatus: 'active',
      },
      {
        $set: { planStatus: 'expired' },
      }
    );

    const updatedUsers = await PaidUser.find({
      expiredDate: { $lte: today },
      planStatus: 'expired',
    });

    return res.status(200).json({
      message: 'Cron job completed successfully',
      expiredLinks: {
        matchedCount: urlUpdateResult.matchedCount || urlUpdateResult.n,
        modifiedCount: urlUpdateResult.modifiedCount || urlUpdateResult.nModified,
        updatedLinks,
      },
      expiredUsers: {
        matchedCount: userUpdateResult.matchedCount || userUpdateResult.n,
        modifiedCount: userUpdateResult.modifiedCount || userUpdateResult.nModified,
        updatedUsers,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: 'Something went wrong', details: error.message });
  }
};

